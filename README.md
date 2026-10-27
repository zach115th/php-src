# Windows builds of the CVE-2026-109618/109619 patch releases

This branch holds only a GitHub Actions workflow and its scripts. It builds the patched PHP 7.x
and 8.x releases (branches `PHP-X.Y.Z-CVE-2026-109618-109619`) and the unpatched releases
(tags `php-X.Y.Z`) on Windows with MSVC, thread-safe and non-thread-safe, and compares them.

## What each job does

1. Checks out the source, the CI scripts and the PHP SDK (`php-sdk-2.3.0`).
2. Installs the Visual Studio toolset the line was released with, when the runner lacks it:
   VS2015 (v140) for 7.0/7.1 and VS2017 (v141) for 7.2-7.4. 8.0/8.1 use VS2019 (v142), which the
   `windows-2022` image has. The VS2015 compiler cannot use the image's newest Windows SDK, so the
   7.0/7.1 jobs build against a Windows 10 SDK (10.0.19041 or older; installed if missing).
   7.0.0-7.0.12 also get the generated-parser fix of 7.0.13 (62bed405da9: `ZEND_API` on the bison 3
   `zendparse()` prototype), patched and unpatched builds alike; the release branches are unchanged.
3. Builds the core with the CLI and CGI SAPIs and the session extension
   (`configure --disable-all --enable-cli --enable-cgi --enable-session`, plus `--disable-zts` for NTS).
4. Runs the checks of the fix (`ci/checks.py`): version string, the out-of-memory exit, the
   `max_multipart_body_parts` limit, multipart and nested input parsing, the stale exception handler
   probe over FastCGI, and `run-tests.php` on Zend/tests, tests/lang, tests/basic and ext/session/tests.

The summary job (`ci/summary.py`) passes a release when the patched build reports `X.Y.Z-p1`, exits
on out-of-memory without running shutdown functions, enforces the part limit, parses multipart and
nested input like the unpatched release, leaves no stale exception handler, and has no new test
failures other than the ones the fix causes. New MSVC warnings are listed for review.

## Running it

Pushing to this branch runs the default selection (`ci/releases.txt`: one release per variant of the
fix). To run another selection, use *Run workflow* with e.g. `7.4`, `7.4.33 8.1.34` or `8.1 ts-only`
(this needs the workflow file on the default branch), or edit `ci/releases.txt` and push.
A run is limited to 256 jobs (a release takes four: TS/NTS x patched/unpatched).
