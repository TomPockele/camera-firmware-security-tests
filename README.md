# camera-firmware-security-tests

Security testing framework to verify password protection in running camera firmware.

## Purpose and scope

This repository is an MVP scaffold for **safe, authorized** password/authentication testing against FCB camera firmware targets. It focuses on non-destructive checks:

- network connectivity to the configured target,
- controlled authentication attempts from user-supplied credentials,
- observation of responses for possible rate limiting (`429`) and lockout-like behavior,
- JSON reporting for repeatable documentation.

> [!WARNING]
> Run these tests only on devices and networks you own or are explicitly authorized to assess.
> Do not use this project for unauthorized access, disruption, persistence, or exploit activity.

## What this MVP does not do

- No exploit development or payload execution
- No brute-force at high volume (attempts are capped)
- No denial-of-service, stealth, persistence, or malware behavior
- No protocol-specific bypass logic

## Repository layout

- `/home/runner/work/camera-firmware-security-tests/camera-firmware-security-tests/scripts/basic_fcb_auth_check.py` — basic safe test harness
- `/home/runner/work/camera-firmware-security-tests/camera-firmware-security-tests/config/example_config.json` — starter config template
- `/home/runner/work/camera-firmware-security-tests/camera-firmware-security-tests/config/credentials_demo.txt` — demo credential list (placeholders only)
- `/home/runner/work/camera-firmware-security-tests/camera-firmware-security-tests/results/` — generated JSON reports

## Prerequisites

- Python 3.10+
- Authorized access to the target camera/firmware interface
- Target host/port and known test credentials (or an approved credential test list)

## Setup

1. Clone this repository.
2. Edit `/home/runner/work/camera-firmware-security-tests/camera-firmware-security-tests/config/example_config.json`:
   - set `target.host`, `target.port`, and transport values,
   - if using HTTP login checks, set `target.auth_endpoint`,
   - provide approved test credentials and/or a credential list,
   - keep `safety.authorized_testing_confirmation` as `I_AM_AUTHORIZED`.
3. Replace `/home/runner/work/camera-firmware-security-tests/camera-firmware-security-tests/config/credentials_demo.txt` with your own approved test inputs.

## Running a basic test

From the repository root:

```bash
python3 scripts/basic_fcb_auth_check.py --config config/example_config.json
```

## Configuration notes

- `auth.max_attempts` is capped to 10 in code for safety.
- `auth.delay_between_attempts_seconds` helps avoid aggressive request behavior.
- If `target.transport` is not HTTP (or no endpoint is provided), the script records connectivity and marks auth checks as protocol-integration TODO.

## Output and artifacts

The script writes a timestamped JSON report to `results/`, for example:

```json
{
  "summary": {
    "connectivity_success": true,
    "attempted_credentials": 3,
    "successful_auth_count": 0,
    "rate_limit_observed": false,
    "lockout_observed": false,
    "default_credentials_tested": ["admin:***", "operator:***"]
  }
}
```

The full report includes:

- target metadata,
- connectivity timing/error details,
- per-attempt status and timing,
- summary indicators for baseline review.

## FCB integration points

Protocol-specific authentication handling is intentionally not hardcoded. Update the TODO-marked branch in `basic_fcb_auth_check.py` to integrate with your approved FCB interface (for example, vendor HTTP API, serial bridge service, or other lab adapter), while keeping checks non-destructive.
