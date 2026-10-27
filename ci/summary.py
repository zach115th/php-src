"""Compare patched and baseline Windows builds and write the run summary.

Usage: python3 ci/summary.py RESULTS_DIR   (each job's artifact is RESULTS_DIR/result-<release>-<ts>-<side>/result.json)
Writes summary.md and summary.json to RESULTS_DIR and to $GITHUB_STEP_SUMMARY; exits 1 if a check fails.
"""
import collections
import json
import os
import re
import sys

# new test failures that the fix itself causes (output changes on the out-of-memory paths)
EXPECTED_FAIL = [r"ext/session/tests/rfc1867", r"tests/lang/bug45392\.phpt",
                 r"Zend/tests/fibers/get-return-after-bailout\.phpt", r"Zend/tests/gh11189(_1)?\.phpt"]


def ver(v):
    return tuple(int(x) for x in v.split("."))


def load(d):
    res = {}
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f, "result.json")
        if f.startswith("result-") and os.path.exists(p):
            r = json.load(open(p))
            res[(r["release"], r["ts"], r["side"])] = r
    return res


def judge(p, b):
    """return (checks dict name -> (ok, detail), notes list)"""
    c, notes = {}, []
    if not p or p.get("build") != "ok":
        c["build"] = (False, "patched build missing" if not p else p.get("build"))
        return c, notes
    c["build"] = (True, "")
    base_ok = bool(b and b.get("build") == "ok")
    if not base_ok:
        notes.append("baseline did not build" if b else "no baseline result")
    v = " ".join(p.get("version") or [])
    c["version"] = (f"{p['release']}-p1" in v, v)
    o = p.get("oom") or {}
    c["oom_exit"] = (o.get("rc") == 1 and "Allowed memory size" in o.get("stderr", "")
                     and "shutdown function ran" not in o.get("stdout", ""),
                     f"rc={o.get('rc')} stderr={o.get('stderr', '').strip()[:120]!r}")
    if "limit20" in p:
        body = p["limit20"].get("body", "")
        c["limit20"] = ("'v19' => 'x'" in body and "'v20'" not in body, body.strip()[:160])
        if base_ok:
            c["mp1_same"] = (p["mp1"].get("body") == b["mp1"].get("body"),
                             f"patched {p['mp1'].get('body', '')[:120]!r} baseline {b['mp1'].get('body', '')[:120]!r}")
            c["nested_same"] = (p["nested"].get("body") == b["nested"].get("body"), "")
        pr = p.get("probe") or []
        c["no_stale_handler"] = (sum("previous exception handler: NULL" in x for x in pr) == 3, " | ".join(pr)[:300])
    else:
        c["cgi"] = (False, "no php-cgi.exe")
    t = p.get("tests") or {}
    if base_ok and b.get("tests"):
        new = sorted(set(t.get("failed", [])) - set(b["tests"].get("failed", [])))
        exp = [x for x in new if any(re.search(e, x) for e in EXPECTED_FAIL) or x in t.get("oom_expect", [])]
        timing = [x for x in new if x not in exp and x in t.get("timing", [])]
        bad = [x for x in new if x not in exp and x not in timing]
        c["tests"] = (not bad, f"passed {t.get('passed')}, new failures: {bad or 'none'}")
        if exp:
            notes.append(f"expected new failures: {', '.join(exp)}")
        if timing:
            notes.append(f"timing-sensitive new failures (not counted): {', '.join(timing)}")
    else:
        notes.append(f"tests: passed {t.get('passed')}, failed {len(t.get('failed', []))} (no baseline to compare)")
    if base_ok:
        key = lambda w: (w[0], w[2], w[3])
        pw = collections.Counter(key(w) for w in p.get("warnings", []))
        bw = collections.Counter(key(w) for w in b.get("warnings", []))
        neww = sorted((pw - bw).elements())
        if neww:
            notes.append("new MSVC warnings: " + "; ".join(f"{f}: {code} {msg}" for f, code, msg in neww[:20]))
    return c, notes


def main(d):
    res = load(d)
    keys = sorted({(r, ts) for r, ts, _ in res}, key=lambda k: (ver(k[0]), k[1]), reverse=True)
    rows, out, failed = [], {}, 0
    for r, ts in keys:
        p, b = res.get((r, ts, "patched")), res.get((r, ts, "baseline"))
        c, notes = judge(p, b)
        ok = all(v[0] for v in c.values())
        failed += not ok
        out[f"{r} {ts}"] = {"ok": ok, "checks": {k: {"ok": v[0], "detail": v[1]} for k, v in c.items()}, "notes": notes}
        mark = lambda k: ("✅" if c[k][0] else "❌") if k in c else "–"
        rows.append(f"| {r} | {ts} | {mark('build')} | {mark('version')} | {mark('oom_exit')} | {mark('limit20')} | "
                    f"{mark('mp1_same')} | {mark('nested_same')} | {mark('no_stale_handler')} | {mark('tests')} | "
                    f"{'pass' if ok else '**FAIL**'} |")
    md = ["# Windows builds of the CVE-2026-109618/109619 patch releases", "",
          f"{len(keys) - failed} of {len(keys)} release/thread-safety combinations pass.", "",
          "| release | ts | build | -p1 | OOM exit | part limit | multipart same | nested same | no stale handler | tests | result |",
          "|---|---|---|---|---|---|---|---|---|---|---|"] + rows + ["", "## Details", ""]
    for k, v in out.items():
        bad = {n: x["detail"] for n, x in v["checks"].items() if not x["ok"]}
        if bad or v["notes"]:
            md.append(f"**{k}**" + (" — FAIL" if not v["ok"] else ""))
            md += [f"- {n}: {det}" for n, det in bad.items()] + [f"- {n}" for n in v["notes"]] + [""]
    text = "\n".join(md) + "\n"
    open(os.path.join(d, "summary.md"), "w", encoding="utf-8").write(text)
    json.dump(out, open(os.path.join(d, "summary.json"), "w"), indent=1)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8").write(text)
    print(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
