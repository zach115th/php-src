"""Run the CVE-2026-109618/109619 checks against a Windows build and record the results.

Usage: python ci/checks.py --src SRC --obj OBJ_DIR --release 7.4.33 --ts ts --side patched --out OUT_DIR

Nothing is judged here; ci/summary.py compares the patched build with the baseline.
"""
import argparse
import glob
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

OOM_TEXT = ["Allowed memory size", "Out of memory", "Possible integer overflow", "String size overflow"]
TIMING = re.compile(r"set_time_limit|max_execution_time|\bu?sleep\(|microtime\(|\btime\(\)")
TEST_DIRS = os.environ.get("CHECKS_TEST_DIRS", "Zend/tests tests/lang tests/basic ext/session/tests").split()

OOM_PHP = """<?php
function on_shutdown() { echo "shutdown function ran\\n"; }
register_shutdown_function('on_shutdown');
ini_set('memory_limit', '4M');
$a = array();
while (true) { $a[] = str_repeat('x', 1024); }
"""
DUMP_PHP = """<?php
echo "POST: ", str_replace("\\n", "", var_export($_POST, true)), "\\n";
foreach ($_FILES as $k => $f) echo "FILE $k: ", $f['name'], " type=", $f['type'], " size=", $f['size'], " err=", $f['error'], "\\n";
"""
NESTED_PHP = """<?php
echo str_replace("\\n", "", var_export($_GET, true)), "\\n";
"""
# headers the fix filters: an unused header, duplicates, and a folded header
MP1 = ("--XyZ\r\nX-Junk: 1\r\nContent-Disposition: form-data; name=\"a\"\r\n"
       "Content-Disposition: form-data; name=\"evil\"\r\n\r\none\r\n"
       "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"t.txt\"\r\n"
       "Content-Type: text/plain\r\nContent-Type: application/evil\r\n\r\nfiledata\r\n"
       "--XyZ\r\nContent-Disposition: form-data;\r\n name=\"folded\"\r\n\r\ntwo\r\n--XyZ--\r\n")
# 25 parts: with max_multipart_body_parts=20, v0..v19 are parsed
MP2 = "".join(f"--XyZ\r\nContent-Disposition: form-data; name=\"v{i}\"\r\n\r\nx\r\n" for i in range(25)) + "--XyZ--\r\n"
NESTED_QS = "a[x][y]=1&a[x][z]=2&a[]=3&a[]=4&a[x][]=5&b[c][d][e]=6&b[c][d][f]=7&b[c][g]=8&s=9"

# stale exception handler probe: request a leaves handlers behind if the bailout path does
# not reset them; the following requests print the previous exception handler
PROBE_A = """<?php
class D {{ function __destruct() {{ file_put_contents({marker!r}, 'dtor ran' . "\\n", FILE_APPEND); exit; }} function h() {{}} }}
function f($e) {{ echo "exception handler f called\\n"; }}
set_exception_handler('f');
function op($p, $n) {{ return true; }} function cl() {{ return true; }} function rd($id) {{ return ''; }}
function wr($id, $d) {{ set_error_handler(array(new D, 'h')); return true; }}
function de($id) {{ return true; }} function gc($l) {{ return true; }}
session_set_save_handler('op', 'cl', 'rd', 'wr', 'de', 'gc');
session_id('abc'); session_start(); $_SESSION['x'] = 1;
echo "a done\\n";
"""
PROBE_C = """<?php
function g($e) {}
$p = set_exception_handler('g');
echo "previous exception handler: ", var_export($p, true), "\\n";
"""


def run(cmd, **kw):
    t = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=kw.pop("timeout", 300), **kw)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = "timeout", e.stdout or b"", e.stderr or b""
    dec = lambda b: b.decode("latin-1") if isinstance(b, bytes) else (b or "")
    return {"rc": rc, "stdout": dec(out), "stderr": dec(err), "seconds": round(time.time() - t, 1)}


def cgi(php_cgi, script, env_extra, body=b"", ini=()):
    env = dict(os.environ, REDIRECT_STATUS="1", GATEWAY_INTERFACE="CGI/1.1", SCRIPT_FILENAME=script, **env_extra)
    args = [php_cgi, "-n", "-d", "display_errors=1", "-d", "html_errors=0"]
    for i in ini:
        args += ["-d", i]
    r = run(args, input=body, env=env, timeout=120)
    out = r["stdout"]
    r["body"] = out.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in out else out
    return r


def fcgi_request(port, script):
    def rec(t, rid, content):
        return struct.pack("!BBHHBx", 1, t, rid, len(content), 0) + content

    def nv(k, v):
        k, v = k.encode(), v.encode()
        enc = lambda n: bytes([n]) if n < 128 else struct.pack("!I", n | 0x80000000)
        return enc(len(k)) + enc(len(v)) + k + v
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    p = b"".join(nv(k, v) for k, v in {"SCRIPT_FILENAME": script, "REQUEST_METHOD": "GET",
                                        "REDIRECT_STATUS": "200", "QUERY_STRING": ""}.items())
    s.sendall(rec(1, 1, struct.pack("!HB5x", 1, 0)) + rec(4, 1, p) + rec(4, 1, b"") + rec(5, 1, b""))
    buf = b""
    while True:
        try:
            d = s.recv(65536)
        except OSError:
            break
        if not d:
            break
        buf += d
    out = b""
    while len(buf) >= 8:
        _, t, _, ln, pad = struct.unpack("!BBHHB", buf[:7])
        if t == 6:
            out += buf[8:8 + ln]
        buf = buf[8 + ln + pad:]
    body = out.split(b"\r\n\r\n", 1)[-1].decode("latin-1").strip()
    return body or "<no response>"


def probe(php_cgi, work, port):
    marker = os.path.join(work, "dtor-marker.txt")
    sess = os.path.join(work, "sess")
    os.makedirs(sess, exist_ok=True)
    a, c = os.path.join(work, "a.php"), os.path.join(work, "c.php")
    open(a, "w").write(PROBE_A.format(marker=marker.replace("\\", "/")))
    open(c, "w").write(PROBE_C)
    env = dict(os.environ, PHP_FCGI_MAX_REQUESTS="1000")
    args = [php_cgi, "-n", "-d", "display_errors=1", "-d", "html_errors=0", "-d", f"session.save_path={sess}",
            "-b", f"127.0.0.1:{port}"]

    def start():
        p = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        return p
    # like a web server's FastCGI process manager, start a new php-cgi when the old one has exited
    # (the fixed builds exit after a fatal error during shutdown instead of serving on)
    out = []
    srv = start()
    try:
        for name, script in (("c", c), ("a", a), ("c", c), ("c", c)):
            if srv.poll() is not None:
                out.append("(php-cgi had exited; started a new one)")
                srv = start()
            try:
                r = fcgi_request(port, script)
            except OSError as e:
                r = f"<error {e}>"
            out.append(f"{name} -> {r[:200]}")
            if r == "<no response>":
                try:
                    srv.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
    finally:
        if srv.poll() is None:
            srv.kill()
    return out


def section(text, names):
    m = re.search(rf"^--(?:{'|'.join(names)})--\r?\n(.*?)(?=^--[A-Z_]+--\r?$|\Z)", text, re.S | re.M)
    return m.group(1) if m else ""


def tests(php, php_cgi, src, out_dir):
    rt = os.path.join(src, "run-tests.php")
    text = open(rt, encoding="latin-1").read()
    parallel = "simultaneous testing processes" in text
    failed_file = os.path.join(out_dir, "failed.txt")
    env = dict(os.environ, NO_INTERACTION="1", REPORT_EXIT_STATUS="0", SKIP_SLOW_TESTS="1",
               TEST_PHP_EXECUTABLE=php, TEST_PHP_CGI_EXECUTABLE=php_cgi)
    cmd = [php, "run-tests.php", "-p", php, "-q", "-w", failed_file, "--set-timeout", "300"]
    if parallel:
        cmd.append("-j4")
    r = run(cmd + TEST_DIRS, cwd=src, env=env, timeout=5400)
    open(os.path.join(out_dir, "run-tests.log"), "w", encoding="latin-1").write(r["stdout"] + r["stderr"])
    failed = []
    if os.path.exists(failed_file):
        for line in open(failed_file, encoding="latin-1"):
            line = line.strip()
            if line:
                p = line.replace("\\", "/")
                s = src.replace("\\", "/").rstrip("/") + "/"
                if p.lower().startswith(s.lower()):
                    p = p[len(s):]
                failed.append(p)
    oom, timing = [], []
    for f in failed:
        try:
            t = open(os.path.join(src, f), encoding="latin-1").read()
        except OSError:
            continue
        if any(x in section(t, ["EXPECT", "EXPECTF", "EXPECTREGEX"]) for x in OOM_TEXT):
            oom.append(f)
        if TIMING.search(t):
            timing.append(f)
    m = re.search(r"Tests passed\s*:\s*(\d+)", r["stdout"])
    return {"passed": int(m.group(1)) if m else None, "failed": sorted(set(failed)), "oom_expect": sorted(oom),
            "timing": sorted(timing), "parallel": parallel, "seconds": r["seconds"], "rc": r["rc"]}


def warnings(log, src):
    res = []
    if not os.path.exists(log):
        return res
    s = src.replace("\\", "/").lower().rstrip("/") + "/"
    for line in open(log, encoding="latin-1"):
        m = re.match(r"^\s*(.+?)\((\d+)\)\s*:\s*warning (C\d+)\s*:\s*(.*)$", line.strip())
        if m:
            p = m.group(1).replace("\\", "/")
            if p.lower().startswith(s):
                p = p[len(s):]
            res.append([p, int(m.group(2)), m.group(3), m.group(4).strip()])
    return res


def main():
    ap = argparse.ArgumentParser()
    for a in ("--src", "--obj", "--release", "--ts", "--side", "--out"):
        ap.add_argument(a, required=True)
    ap.add_argument("--log", default="")
    ap.add_argument("--port", type=int, default=9123)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    res = {"release": a.release, "ts": a.ts, "side": a.side}
    res["warnings"] = warnings(a.log, a.src)
    phps = glob.glob(os.path.join(a.obj, "**", "php.exe"), recursive=True)
    if not phps:
        res["build"] = "no php.exe"
        json.dump(res, open(os.path.join(a.out, "result.json"), "w"), indent=1)
        print("no php.exe found under", a.obj)
        return 1
    php = phps[0]
    php_cgi = os.path.join(os.path.dirname(php), "php-cgi.exe")
    res["build"] = "ok"
    res["php"] = php
    res["version"] = run([php, "-n", "-v"])["stdout"].splitlines()[:1]
    work = tempfile.mkdtemp(prefix="cvechk-")
    for name, content in (("oom.php", OOM_PHP), ("dump.php", DUMP_PHP), ("nested.php", NESTED_PHP)):
        open(os.path.join(work, name), "w").write(content)
    res["oom"] = run([php, "-n", "-d", "display_errors=1", os.path.join(work, "oom.php")])
    if os.path.exists(php_cgi):
        mp = {"REQUEST_METHOD": "POST", "CONTENT_TYPE": "multipart/form-data; boundary=XyZ"}
        res["mp1"] = cgi(php_cgi, os.path.join(work, "dump.php"), dict(mp, CONTENT_LENGTH=str(len(MP1))), MP1.encode())
        res["limit20"] = cgi(php_cgi, os.path.join(work, "dump.php"), dict(mp, CONTENT_LENGTH=str(len(MP2))), MP2.encode(),
                             ini=["max_multipart_body_parts=20"])
        res["nested"] = cgi(php_cgi, os.path.join(work, "nested.php"), {"REQUEST_METHOD": "GET", "QUERY_STRING": NESTED_QS})
        try:
            res["probe"] = probe(php_cgi, work, a.port)
        except Exception as e:
            res["probe"] = [f"<probe error {e!r}>"]
    res["tests"] = tests(php, php_cgi, a.src, a.out)
    json.dump(res, open(os.path.join(a.out, "result.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k not in ("warnings",)}, indent=1)[:6000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
