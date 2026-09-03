#!/usr/bin/env python3
"""Basic, non-destructive authentication checks for camera firmware targets.

This script is intentionally protocol-agnostic with optional HTTP auth probing.
Use only on systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request


AUTH_CONFIRMATION_TOKEN = "I_AM_AUTHORIZED"


@dataclass
class Credential:
    username: str
    password: str


class ConfigError(Exception):
    pass


def load_config(config_path: Path) -> dict[str, Any]:
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in config file: {exc}") from exc


def validate_authorization(config: dict[str, Any]) -> None:
    token = config.get("safety", {}).get("authorized_testing_confirmation", "")
    if token != AUTH_CONFIRMATION_TOKEN:
        raise ConfigError(
            "Authorization confirmation missing. Set "
            "safety.authorized_testing_confirmation to 'I_AM_AUTHORIZED'."
        )


def parse_wordlist(wordlist_path: Path) -> list[Credential]:
    credentials: list[Credential] = []
    if not wordlist_path.exists():
        return credentials

    for line in wordlist_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        username, password = stripped.split(":", 1)
        credentials.append(Credential(username.strip(), password.strip()))
    return credentials


def build_credential_set(config: dict[str, Any], config_path: Path) -> list[Credential]:
    auth_cfg = config.get("auth", {})
    candidates: list[Credential] = []

    username = auth_cfg.get("username")
    password = auth_cfg.get("password")
    if username and password:
        candidates.append(Credential(username, password))

    wordlist_value = auth_cfg.get("credential_wordlist")
    if wordlist_value:
        wordlist_path = (config_path.parent / wordlist_value).resolve()
        candidates.extend(parse_wordlist(wordlist_path))

    unique: list[Credential] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        key = (item.username, item.password)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def check_connectivity(host: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        "success": False,
        "host": host,
        "port": port,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["success"] = True
    except OSError as exc:
        result["error"] = str(exc)
    finally:
        result["response_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def attempt_http_auth(url: str, credential: Credential, timeout: float) -> dict[str, Any]:
    payload = json.dumps(
        {
            "username": credential.username,
            "password": credential.password,
        }
    ).encode("utf-8")
    req = request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    started = time.perf_counter()

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "status_code": resp.getcode(),
                "body_excerpt": body[:200],
                "response_ms": round((time.perf_counter() - started) * 1000, 2),
            }
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "status_code": exc.code,
            "body_excerpt": body[:200],
            "response_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status_code": None,
            "body_excerpt": "",
            "response_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(exc),
        }


def run_checks(config: dict[str, Any], config_path: Path) -> dict[str, Any]:
    target_cfg = config.get("target", {})
    auth_cfg = config.get("auth", {})

    host = target_cfg.get("host", "")
    port = int(target_cfg.get("port", 0))
    timeout = float(target_cfg.get("timeout_seconds", 3))

    if not host or not port:
        raise ConfigError("target.host and target.port are required")

    transport = str(target_cfg.get("transport", "tcp")).lower()
    auth_endpoint = target_cfg.get("auth_endpoint")

    max_attempts_cfg = int(auth_cfg.get("max_attempts", 3))
    max_attempts = max(0, min(max_attempts_cfg, 10))
    delay_seconds = float(auth_cfg.get("delay_between_attempts_seconds", 1.0))
    stop_on_first_success = bool(auth_cfg.get("stop_on_first_success", True))

    connectivity = check_connectivity(host=host, port=port, timeout=timeout)
    credentials = build_credential_set(config=config, config_path=config_path)

    auth_attempts: list[dict[str, Any]] = []
    rate_limit_observed = False
    lockout_observed = False

    if connectivity["success"] and credentials and max_attempts > 0:
        attempts = credentials[:max_attempts]
        for index, credential in enumerate(attempts, start=1):
            if transport == "http" and auth_endpoint:
                url = auth_endpoint
                if auth_endpoint.startswith("/"):
                    url = f"http://{host}:{port}{auth_endpoint}"
                response = attempt_http_auth(url=url, credential=credential, timeout=timeout)
                status_code = response.get("status_code")
                excerpt = str(response.get("body_excerpt", "")).lower()
                rate_limit_observed = rate_limit_observed or status_code == 429
                lockout_observed = lockout_observed or ("lock" in excerpt and "account" in excerpt)
                auth_success = status_code in (200, 204)
            else:
                # TODO: Replace this branch with FCB protocol-specific auth integration.
                response = {
                    "status_code": None,
                    "body_excerpt": "Protocol-specific auth not implemented.",
                    "response_ms": 0.0,
                }
                auth_success = False

            auth_attempts.append(
                {
                    "attempt": index,
                    "username": credential.username,
                    "status_code": response.get("status_code"),
                    "response_ms": response.get("response_ms"),
                    "result": "success" if auth_success else "failure_or_unknown",
                    "notes": response.get("error") or response.get("body_excerpt"),
                }
            )

            if auth_success and stop_on_first_success:
                break
            if index < len(attempts):
                time.sleep(max(0.0, delay_seconds))

    summary = {
        "connectivity_success": connectivity["success"],
        "attempted_credentials": len(auth_attempts),
        "successful_auth_count": sum(1 for item in auth_attempts if item["result"] == "success"),
        "rate_limit_observed": rate_limit_observed,
        "lockout_observed": lockout_observed,
        "default_credentials_tested": [f"{c.username}:***" for c in credentials[:max_attempts]],
    }

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": {
            "host": host,
            "port": port,
            "transport": transport,
            "auth_endpoint": auth_endpoint,
        },
        "connectivity": connectivity,
        "auth_attempts": auth_attempts,
        "summary": summary,
    }


def write_report(config: dict[str, Any], report: dict[str, Any]) -> Path:
    report_cfg = config.get("report", {})
    output_dir = Path(str(report_cfg.get("output_dir", "results"))).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    prefix = str(report_cfg.get("output_prefix", "fcb-basic-auth"))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"{prefix}-{timestamp}.json"
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run basic, non-destructive auth checks against camera firmware targets."
    )
    parser.add_argument(
        "--config",
        default="config/example_config.json",
        help="Path to JSON configuration file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()

    try:
        config = load_config(config_path)
        validate_authorization(config)
        report = run_checks(config=config, config_path=config_path)
        output_path = write_report(config=config, report=report)
        print(f"Report written to: {output_path}")
        print(json.dumps(report["summary"], indent=2))
        return 0
    except ConfigError as exc:
        print(f"Configuration error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
