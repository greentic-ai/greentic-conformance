#!/usr/bin/env python3
import argparse
import json
import os
import ssl
import sys
import time
from typing import Iterable
import urllib.error
import urllib.parse
import urllib.request

ACCEPTABLE_RESULTS = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}
ALLOWED_SCHEMES = {"http", "https"}


def validate_url(url: str, allowed_hosts: Iterable[str] | None = None) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported URL scheme for RP URL: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError("RP URL must include a host")

    if allowed_hosts is not None:
        host = parsed.hostname or ""
        if host not in allowed_hosts:
            raise ValueError(f"Host {host!r} is not in the allowed host list")

    return url


def build_client(base_url, token, *, insecure=False):
    base_url = validate_url(base_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    parsed = urllib.parse.urlparse(base_url)
    use_context = parsed.scheme == "https"
    if use_context:
        ssl_context = ssl.create_default_context()
    else:
        ssl_context = None

    def request(method, path, *, params=None, data=None, timeout=30):
        url = urllib.parse.urljoin(base_url, path.lstrip("/"))
        if params:
            query = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}?{query}"
        payload = None
        if data is not None:
            if isinstance(data, (dict, list)):
                payload = json.dumps(data).encode("utf-8")
            elif isinstance(data, str):
                payload = data.encode("utf-8")
            else:
                payload = data
        req = urllib.request.Request(url, data=payload, method=method)
        for key, value in headers.items():
            req.add_header(key, value)
        if payload is None:
            req.add_header("Content-Length", "0")
        try:
            if ssl_context is not None:
                resp_ctx = urllib.request.urlopen(req, timeout=timeout, context=ssl_context)
            else:
                resp_ctx = urllib.request.urlopen(req, timeout=timeout)
            with resp_ctx as resp:
                body = resp.read()
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            body = e.read()
            message = body.decode("utf-8", "ignore")
            raise RuntimeError(f"{method} {url} failed: {e.code} {message}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"{method} {url} failed: {e.reason}") from e

        if ctype.startswith("application/json"):
            if not body:
                return {}
            return json.loads(body.decode("utf-8"))
        return body.decode("utf-8")

    return request


def read_plan_id(explicit_plan_id, root):
    if explicit_plan_id:
        return explicit_plan_id
    plan_file = os.path.join(root, "reports", ".last_plan_id")
    if os.path.isfile(plan_file):
        with open(plan_file, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
            if value:
                return value
    raise RuntimeError("Unable to determine plan id (pass --plan-id or run plan creation first)")


def start_module(client, module_id):
    try:
        client("POST", f"/api/runner/{module_id}", data="")
    except RuntimeError:
        client("POST", f"/api/runner/{module_id}/start", data="")


def trigger_rp(trigger_url, module_id, alias, issuer, *, insecure=False):
    trigger_url = validate_url(trigger_url)
    payload = json.dumps({
        "module_id": module_id,
        "alias": alias,
        "issuer": issuer,
    }).encode("utf-8")
    req = urllib.request.Request(trigger_url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    parsed = urllib.parse.urlparse(trigger_url)
    if parsed.scheme == "https":
        context = ssl.create_default_context()
    else:
        context = None
    try:
        if context is not None:
            resp_ctx = urllib.request.urlopen(req, timeout=30, context=context)
        else:
            resp_ctx = urllib.request.urlopen(req, timeout=30)
        with resp_ctx as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        message = e.read().decode("utf-8", "ignore")
        raise RuntimeError(f"RP trigger failed ({e.code}): {message}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"RP trigger failed: {e.reason}") from e


def poll_module(client, module_id, *, fail_fast):
    deadline = time.time() + 900
    last_status = None
    while time.time() < deadline:
        info = client("GET", f"/api/info/{module_id}")
        status = info.get("status")
        result = info.get("result")
        print(f"[rp-driver] {module_id} status={status} result={result}", flush=True)
        if status in {"FINISHED", "INTERRUPTED"}:
            if status != "FINISHED" or result not in ACCEPTABLE_RESULTS:
                if fail_fast:
                    raise RuntimeError(f"Module {module_id} ended with status={status} result={result}")
                return False
            return True
        time.sleep(2)
        last_status = status
    if fail_fast:
        raise RuntimeError(f"Module {module_id} timed out (last status={last_status})")
    return False


def ensure_modules(client, plan_id):
    detail = client("GET", f"/api/plan/{plan_id}")
    modules = detail.get("modules") or []
    normalized = []
    for module in modules:
        module_id = module.get("moduleId") or module.get("id") or module.get("_id")
        if not module_id:
            continue
        normalized.append({
            "id": module_id,
            "name": module.get("testModule") or module.get("name"),
            "status": module.get("status"),
        })
    if not normalized:
        raise RuntimeError("Plan contains no modules; ensure run-test-plan.py created them")
    return normalized


def drive_modules(client, *, plan_id, alias, trigger_url, server_base, fail_fast, insecure_trigger=False):
    issuer = urllib.parse.urljoin(server_base.rstrip("/") + "/", f"test/a/{alias}/")
    modules = ensure_modules(client, plan_id)
    overall_success = True

    for module in modules:
        module_id = module["id"]
        print(f"[rp-driver] processing module {module.get('name')} ({module_id})", flush=True)
        info = client("GET", f"/api/info/{module_id}")
        status = info.get("status")
        if status == "CREATED":
            print(f"[rp-driver] starting module {module_id}", flush=True)
            start_module(client, module_id)
            status = "WAITING"

        if status == "CONFIGURED":
            start_module(client, module_id)
            status = "WAITING"

        if status == "WAITING":
            print(f"[rp-driver] triggering RP for module {module_id}", flush=True)
            try:
                trigger_rp(trigger_url, module_id, alias, issuer, insecure=insecure_trigger)
            except RuntimeError as exc:
                print(f"[rp-driver] {exc}", file=sys.stderr, flush=True)
                if fail_fast:
                    raise
                overall_success = False
                continue

        try:
            ok = poll_module(client, module_id, fail_fast=fail_fast)
        except RuntimeError as exc:
            print(f"[rp-driver] {exc}", file=sys.stderr, flush=True)
            if fail_fast:
                raise
            overall_success = False
            continue

        overall_success = overall_success and ok

    return overall_success


def main():
    parser = argparse.ArgumentParser(description="Drive OIDF RP modules by triggering the RP harness")
    parser.add_argument("--server", required=True, help="OIDF suite base URL")
    parser.add_argument("--token", required=True, help="OIDF suite bearer token")
    parser.add_argument("--alias", required=True, help="RP alias registered with the suite")
    parser.add_argument("--trigger", required=True, help="RP endpoint that initiates the login flow")
    parser.add_argument("--plan-id", help="Plan identifier (optional, read from reports/.last_plan_id if omitted)")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first module failure")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification when talking to the suite/RP")
    args = parser.parse_args()

    if args.insecure:
        print("[rp-driver] '--insecure' is no longer supported; using secure TLS validation.", flush=True)

    server_url = validate_url(args.server)
    base_url = server_url.rstrip("/") + "/"
    client = build_client(base_url, args.token, insecure=args.insecure)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    plan_id = read_plan_id(args.plan_id, root)
    print(f"[rp-driver] using plan {plan_id}", flush=True)

    trigger_url = validate_url(args.trigger)
    try:
        success = drive_modules(
            client,
            plan_id=plan_id,
            alias=args.alias,
            trigger_url=trigger_url,
            server_base=base_url,
            fail_fast=args.fail_fast,
            insecure_trigger=args.insecure,
        )
    except RuntimeError as exc:
        print(f"[rp-driver] {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
