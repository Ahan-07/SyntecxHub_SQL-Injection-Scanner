#!/usr/bin/env python3
"""
SQL Injection Scanner - Local/Lab Edition

Safety:
- Only localhost/loopback targets are accepted.
- No arbitrary remote scanning.
- Small bounded payload set.
- Concurrency and rate limiting are intentionally conservative.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from scanner.detector import (
    classify_error_response,
    compare_boolean_responses,
    response_fingerprint,
)
from scanner.http_client import HttpClient, RequestResult
from scanner.payloads import BOOLEAN_CASES, ERROR_PAYLOADS
from scanner.rate_limiter import RateLimiter
from scanner.reporter import ReportWriter


LOG = logging.getLogger("sqli-scanner")


@dataclass
class Finding:
    url: str
    method: str
    parameter: str
    test_type: str
    confidence: str
    evidence: str
    baseline_status: int
    test_status: int
    baseline_length: int
    test_length: int
    payload: str
    timestamp: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local/lab SQL injection indicator scanner."
    )
    parser.add_argument("--url", required=True, help="Authorized local target URL.")
    parser.add_argument(
        "--method", choices=["GET", "POST"], default="GET",
        help="HTTP method. Default: GET."
    )
    parser.add_argument(
        "--data",
        default="",
        help="POST form data, e.g. username=test&password=test",
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help="Maximum requests/second across workers. Use 0 for no artificial limit.",
    )
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument(
        "--format",
        choices=["json", "csv", "both"],
        default="both",
    )
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def validate_local_target(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// or https:// URLs are accepted.")

    if not parsed.hostname:
        raise ValueError("Target URL has no hostname.")

    host = parsed.hostname.lower().rstrip(".")

    allowed = {"localhost", "127.0.0.1", "::1"}
    if host not in allowed:
        raise ValueError(
            f"Safety restriction: '{host}' is not a local target. "
            "Use localhost/127.0.0.1/::1 only."
        )


def parse_form_data(data: str) -> Dict[str, str]:
    if not data:
        return {}
    pairs = parse_qsl(data, keep_blank_values=True)
    return dict(pairs)


def replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)

    changed = False
    new_query = []

    for key, old_value in query:
        if key == parameter and not changed:
            new_query.append((key, value))
            changed = True
        else:
            new_query.append((key, old_value))

    return urlunparse(parsed._replace(query=urlencode(new_query)))


def prepare_parameters(url: str, method: str, data: str) -> Dict[str, str]:
    if method == "GET":
        return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    return parse_form_data(data)


def build_post_data(original: Dict[str, str], parameter: str, value: str) -> Dict[str, str]:
    data = dict(original)
    data[parameter] = value
    return data


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_error_payload(
    client: HttpClient,
    limiter: RateLimiter,
    base_url: str,
    method: str,
    original_data: Dict[str, str],
    parameter: str,
    baseline: RequestResult,
    payload: str,
) -> Optional[Finding]:

    limiter.wait()

    if method == "GET":
        target = replace_query_parameter(base_url, parameter, payload)
        result = client.request("GET", target)
    else:
        result = client.request(
            "POST",
            base_url,
            data=build_post_data(original_data, parameter, payload),
        )

    if result.error:
        LOG.warning("Request error for %s/%s: %s", parameter, payload, result.error)
        return None

    evidence = classify_error_response(result.text)
    if not evidence:
        return None

    return Finding(
        url=base_url,
        method=method,
        parameter=parameter,
        test_type="error-based",
        confidence="MEDIUM",
        evidence=evidence,
        baseline_status=baseline.status_code,
        test_status=result.status_code,
        baseline_length=len(baseline.text),
        test_length=len(result.text),
        payload=payload,
        timestamp=utc_now(),
    )


def scan_boolean_pair(
    client: HttpClient,
    limiter: RateLimiter,
    base_url: str,
    method: str,
    original_data: Dict[str, str],
    parameter: str,
    baseline: RequestResult,
    true_payload: str,
    false_payload: str,
) -> Optional[Finding]:

    def request_value(value: str) -> RequestResult:
        limiter.wait()
        if method == "GET":
            target = replace_query_parameter(base_url, parameter, value)
            return client.request("GET", target)
        return client.request(
            "POST",
            base_url,
            data=build_post_data(original_data, parameter, value),
        )

    true_result = request_value(true_payload)
    false_result = request_value(false_payload)

    if true_result.error or false_result.error:
        return None

    matched, evidence = compare_boolean_responses(
        baseline.text,
        true_result.text,
        false_result.text,
        baseline.status_code,
        true_result.status_code,
        false_result.status_code,
    )

    if not matched:
        return None

    return Finding(
        url=base_url,
        method=method,
        parameter=parameter,
        test_type="boolean-based",
        confidence="HIGH",
        evidence=evidence,
        baseline_status=baseline.status_code,
        test_status=true_result.status_code,
        baseline_length=len(baseline.text),
        test_length=len(true_result.text),
        payload=f"TRUE={true_payload} | FALSE={false_payload}",
        timestamp=utc_now(),
    )


def main() -> int:
    args = parse_args()

    if args.workers < 1 or args.workers > 8:
        print("workers must be between 1 and 8.", file=sys.stderr)
        return 2

    if args.rate < 0 or args.rate > 20:
        print("rate must be between 0 and 20 requests/second.", file=sys.stderr)
        return 2

    try:
        validate_local_target(args.url)
    except ValueError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    parameters = prepare_parameters(args.url, args.method, args.data)

    if not parameters:
        print(
            "[INFO] No parameters found. Add a query parameter for GET or "
            "--data for POST."
        )
        return 0

    LOG.info("Target accepted: local/lab scope")
    LOG.info("Parameters: %s", ", ".join(parameters))
    LOG.info("Workers=%d rate=%s req/s", args.workers, args.rate)

    limiter = RateLimiter(args.rate)
    client = HttpClient(timeout=args.timeout, verify_tls=args.verify_tls)

    # Baseline request.
    limiter.wait()
    if args.method == "GET":
        baseline = client.request("GET", args.url)
    else:
        baseline = client.request(
            "POST", args.url, data=parse_form_data(args.data)
        )

    if baseline.error:
        LOG.error("Baseline request failed: %s", baseline.error)
        return 1

    LOG.info(
        "Baseline: status=%d length=%d fingerprint=%s",
        baseline.status_code,
        len(baseline.text),
        response_fingerprint(baseline.text),
    )

    findings: List[Finding] = []
    lock = Lock()

    tasks = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for parameter in parameters:
            for payload in ERROR_PAYLOADS:
                tasks.append(
                    executor.submit(
                        scan_error_payload,
                        client,
                        limiter,
                        args.url,
                        args.method,
                        parse_form_data(args.data),
                        parameter,
                        baseline,
                        payload,
                    )
                )

            for true_payload, false_payload in BOOLEAN_CASES:
                tasks.append(
                    executor.submit(
                        scan_boolean_pair,
                        client,
                        limiter,
                        args.url,
                        args.method,
                        parse_form_data(args.data),
                        parameter,
                        baseline,
                        true_payload,
                        false_payload,
                    )
                )

        for future in as_completed(tasks):
            try:
                finding = future.result()
                if finding:
                    with lock:
                        findings.append(finding)
                        LOG.warning(
                            "Possible SQLi: parameter=%s type=%s confidence=%s",
                            finding.parameter,
                            finding.test_type,
                            finding.confidence,
                        )
            except Exception:
                LOG.exception("Worker failed")

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    writer = ReportWriter(output)
    report_data = {
        "scanner": "SQL Injection Scanner - Local/Lab Edition",
        "generated_at": utc_now(),
        "target": args.url,
        "method": args.method,
        "parameters": list(parameters.keys()),
        "requests": limiter.count,
        "findings": [asdict(f) for f in findings],
    }

    if args.format in {"json", "both"}:
        writer.write_json(report_data)

    if args.format in {"csv", "both"}:
        writer.write_csv(findings)

    print("\nScan complete.")
    print(f"Requests: {limiter.count}")
    print(f"Findings: {len(findings)}")
    print(f"Reports: {output.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
