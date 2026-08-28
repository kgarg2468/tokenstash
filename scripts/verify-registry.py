#!/usr/bin/env python3
"""Empirically verify registry/providers.json against the live world.

Two sweeps, both read-only:

  urls    GET every provider `url` (the page a human is sent to to create a key)
          with redirects followed and a browser-ish User-Agent. Records the
          final HTTP status and the final URL, so a silent redirect of a dead
          deep link onto a marketing homepage is visible rather than a green 200.

  checks  Call every provider `check` (the liveness probe) with an obviously
          invalid credential, using the exact auth style the registry declares.
          The contract a good check must satisfy: an invalid key produces
          401/403 (or the provider's documented auth-failure code). A 404 means
          the endpoint is wrong, a 400 "unknown header" means the auth style is
          wrong, and a 200 means the endpoint does not require auth at all and
          the check is therefore meaningless.

No real credential is ever read, sent or stored: the probe value is a constant
string that is not a key for anything.

Usage:
    scripts/verify-registry.py                 # both sweeps, print the table
    scripts/verify-registry.py urls
    scripts/verify-registry.py checks
    scripts/verify-registry.py --json out.json # also dump raw results
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, os.pardir, "crates", "core", "registry", "providers.json")

# Not a credential for anything. Deliberately shaped like nothing.
FAKE = "tokenstash-invalid-credential-000000000000"

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
TIMEOUT = 20
PER_HOST_DELAY = 1.0  # be polite: at most ~1 request per second per host

_last_hit: dict[str, float] = defaultdict(float)


def polite(url: str) -> None:
    host = urllib.parse.urlparse(url).netloc
    wait = _last_hit[host] + PER_HOST_DELAY - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last_hit[host] = time.monotonic()


class Redirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects but remember the chain, so a deep link that lands on a
    homepage is distinguishable from one that actually resolved."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.redirect_chain = getattr(req, "redirect_chain", []) + [newurl]
        return new


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def fetch(url: str, method: str = "GET", headers: dict | None = None,
          body: bytes | None = None, follow: bool = True) -> dict:
    """One request. Returns status/final url/first bytes of body, never raises."""
    polite(url)
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, method=method, headers=hdrs, data=body)
    req.redirect_chain = []
    ctx = ssl.create_default_context()
    handlers = [Redirects()] if follow else [NoRedirect()]
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), *handlers)
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            payload = resp.read(2048)
            return {
                "status": resp.status,
                "final_url": resp.geturl(),
                "body": payload.decode("utf-8", "replace"),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        payload = b""
        try:
            payload = e.read(2048)
        except Exception:
            pass
        return {
            "status": e.code,
            "final_url": e.geturl() if hasattr(e, "geturl") else url,
            "body": payload.decode("utf-8", "replace"),
            "error": None,
        }
    except Exception as e:  # DNS, TLS, timeout, refused
        return {"status": None, "final_url": url, "body": "",
                "error": f"{type(e).__name__}: {e}"}


def apply_auth(check: dict, value: str) -> tuple[str, dict]:
    """Mirror crates/core/src/validate.rs::liveness exactly, so what this script
    probes is what the binary will actually send."""
    url = check["url"]
    auth = check.get("auth", "")
    headers: dict[str, str] = {}
    if auth == "bearer":
        headers["Authorization"] = f"Bearer {value}"
    elif auth == "basic-user":
        b = base64.b64encode(f"{value}:".encode()).decode()
        headers["Authorization"] = f"Basic {b}"
    elif auth.startswith("header:"):
        headers[auth[len("header:"):]] = value
    elif auth.startswith("prefix:"):
        headers["Authorization"] = f"{auth[len('prefix:'):]} {value}"
    elif auth.startswith("query:"):
        param = auth[len("query:"):]
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{param}={urllib.parse.quote(value)}"
    headers.update(check.get("headers", {}))
    return url, headers


def same_page(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    ha = pa.netloc.removeprefix("www.")
    hb = pb.netloc.removeprefix("www.")
    return ha == hb and pa.path.rstrip("/") == pb.path.rstrip("/")


def classify_url(url: str, r: dict) -> str:
    if r["error"]:
        return "BROKEN"
    s = r["status"]
    if s is None or s >= 500 or s in (404, 410):
        return "BROKEN"
    if s >= 400:
        # 401/403 on a console deep link is a login wall, which is fine.
        return "OK" if s in (401, 403) else "BROKEN"
    if same_page(url, r["final_url"]):
        return "OK"
    return "REDIRECTED"


def classify_check(r: dict, declared_reject: list | None = None) -> str:
    if r["error"]:
        return "UNREACHABLE"
    s = r["status"]
    if s in (401, 403):
        return "OK"
    if s in (declared_reject or []):
        # The provider's documented auth-failure code is not 401/403, and the
        # registry says so via `reject_status`, so the probe does reject.
        return "OK-DECLARED"
    if s == 200:
        # Some APIs answer 200 with an error envelope (Slack's Web API always
        # does). liveness() only ever sees the status, so a 200 is accepted no
        # matter what the body says: the probe cannot reject anything.
        low = r["body"].lower().replace(" ", "")
        if '"ok":false' in low or '"error"' in low:
            return "NO-AUTH-STATUS"
        return "NO-AUTH"
    if s == 404:
        return "BAD-ENDPOINT"
    if s == 400:
        return "BAD-AUTH-STYLE"
    return f"HTTP-{s}"


def load() -> list[dict]:
    with open(REGISTRY, encoding="utf-8") as f:
        return json.load(f)["providers"]


def sweep_urls(providers: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    out = []
    for p in providers:
        url = p["url"]
        if url not in seen:
            seen[url] = fetch(url)
        r = seen[url]
        out.append({
            "name": p["name"], "url": url, "status": r["status"],
            "final_url": r["final_url"], "error": r["error"],
            "verdict": classify_url(url, r),
        })
        print(f"  url  {p['name']:36} {str(r['status'] or r['error'])[:28]:30} "
              f"{out[-1]['verdict']:11} {r['final_url'][:80]}", file=sys.stderr)
    return out


def sweep_checks(providers: list[dict]) -> list[dict]:
    out = []
    for p in providers:
        c = p.get("check")
        if not c:
            continue
        url, headers = apply_auth(c, FAKE)
        method = c.get("method", "GET").upper()
        body = None
        if method == "POST":
            body = b"{}"
            headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        r = fetch(url, method=method, headers=headers, body=body, follow=False)
        out.append({
            "name": p["name"], "url": c["url"], "auth": c.get("auth"),
            "method": method, "status": r["status"], "error": r["error"],
            "body": r["body"][:300],
            "verdict": classify_check(r, c.get("reject_status")),
        })
        print(f"  chk  {p['name']:36} {str(r['status'] or r['error'])[:28]:30} "
              f"{out[-1]['verdict']:14} {r['body'][:70]!r}", file=sys.stderr)
    return out


def table(urls: list[dict], checks: list[dict]) -> str:
    by_check = {c["name"]: c for c in checks}
    lines = [
        "| name | url verdict | url status | final url | check verdict | check status |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for u in urls:
        c = by_check.get(u["name"])
        final = u["final_url"] if u["verdict"] == "REDIRECTED" else ""
        lines.append(
            f"| {u['name']} | {u['verdict']} | {u['status'] or u['error']} | {final} | "
            f"{c['verdict'] if c else '-'} | {(c['status'] or c['error']) if c else '-'} |"
        )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sweep", nargs="?", default="all", choices=["all", "urls", "checks"])
    ap.add_argument("--json", help="dump raw results here")
    ap.add_argument("--only", help="comma-separated env var names to probe")
    args = ap.parse_args()

    providers = load()
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        providers = [p for p in providers if p["name"] in want]

    urls = sweep_urls(providers) if args.sweep in ("all", "urls") else []
    checks = sweep_checks(providers) if args.sweep in ("all", "checks") else []

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"urls": urls, "checks": checks}, f, indent=2)

    print(table(urls, checks))
    bad = sum(1 for u in urls if u["verdict"] == "BROKEN")
    bad += sum(1 for c in checks if c["verdict"] not in ("OK", "OK-DECLARED"))
    print(f"\n{len(urls)} urls, {len(checks)} checks, {bad} needing attention",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
