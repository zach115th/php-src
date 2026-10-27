"""Build the job matrix for the Windows workflow.

Usage: python3 ci/matrix.py "<selection>" >> "$GITHUB_OUTPUT"

The selection is a space-separated list of:
  list          the releases in ci/releases.txt (the default)
  7.4           every patched release of a line (from the PHP-*-CVE-2026-109618-109619 branches)
  7.4.33        one release
  ts-only, nts-only, patched-only   restrict the builds
"""
import json
import os
import re
import subprocess
import sys

SUF = "-CVE-2026-109618-109619"
HERE = os.path.dirname(os.path.abspath(__file__))
MAX_JOBS = 256  # GitHub's limit for one matrix

# Visual Studio toolset per line (the CRT PHP used for its Windows builds of that line).
# The hosted windows-2022 image has Visual Studio 2022 with the VS2019 (v142) toolset; the
# VS2015 (v140) and VS2017 (v141) toolsets are optional components installed by the job.
TOOLCHAINS = {
    "7.0": dict(crt="vc14", starter="vc15", toolset="14.0", component="Microsoft.VisualStudio.Component.VC.140"),
    "7.1": dict(crt="vc14", starter="vc15", toolset="14.0", component="Microsoft.VisualStudio.Component.VC.140"),
    "7.2": dict(crt="vc15", starter="vc15", toolset="14.16", component="Microsoft.VisualStudio.Component.VC.v141.x86.x64"),
    "7.3": dict(crt="vc15", starter="vc15", toolset="14.16", component="Microsoft.VisualStudio.Component.VC.v141.x86.x64"),
    "7.4": dict(crt="vc15", starter="vc15", toolset="14.16", component="Microsoft.VisualStudio.Component.VC.v141.x86.x64"),
    "8.0": dict(crt="vs16", starter="vs16", toolset="14.2", component=""),
    "8.1": dict(crt="vs16", starter="vs16", toolset="14.2", component=""),
}


def ver(v):
    return tuple(int(x) for x in v.split("."))


def patched_releases():
    url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'zach115th/php-src')}"
    out = subprocess.run(["git", "ls-remote", "--heads", url, f"PHP-*{SUF}"],
                         capture_output=True, text=True, check=True).stdout
    return sorted({m.group(1) for m in re.finditer(rf"refs/heads/PHP-(\d+\.\d+\.\d+){re.escape(SUF)}$", out, re.M)}, key=ver)


def main(selection):
    tokens = selection.split() or ["list"]
    flags = {t for t in tokens if t.endswith("-only")}
    tokens = [t for t in tokens if not t.endswith("-only")]
    known = None
    releases = []
    for t in tokens:
        if t == "list":
            for line in open(os.path.join(HERE, "releases.txt")):
                line = line.split("#", 1)[0]
                releases += line.split()
        elif re.fullmatch(r"\d+\.\d+", t):
            known = known or patched_releases()
            releases += [r for r in known if r.rsplit(".", 1)[0] == t]
        elif re.fullmatch(r"\d+\.\d+\.\d+", t):
            releases.append(t)
        else:
            sys.exit(f"unknown selection token: {t}")
    # oldest first: their jobs install a Visual Studio toolset and take longest
    releases = sorted(set(releases), key=ver)
    if not releases:
        sys.exit("no releases selected")

    include = []
    for r in releases:
        line = r.rsplit(".", 1)[0]
        if line not in TOOLCHAINS:
            sys.exit(f"{r}: no Windows toolchain configured for PHP {line}")
        tc = TOOLCHAINS[line]
        for ts in (["ts"] if "ts-only" in flags else ["nts"] if "nts-only" in flags else ["ts", "nts"]):
            for side in (["patched"] if "patched-only" in flags else ["patched", "baseline"]):
                include.append(dict(
                    name=f"{r} {ts} {side}", release=r, line=line, ts=ts, side=side,
                    ref=f"PHP-{r}{SUF}" if side == "patched" else f"refs/tags/php-{r}",
                    **tc))
    if len(include) > MAX_JOBS:
        sys.exit(f"{len(include)} jobs selected; GitHub allows {MAX_JOBS} per run. "
                 f"Select fewer releases or use ts-only / nts-only / patched-only.")
    print(f"include={json.dumps(include, separators=(',', ':'))}")
    print(f"count={len(include)}")
    print(f"selected {len(releases)} release(s), {len(include)} job(s)", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "list")
