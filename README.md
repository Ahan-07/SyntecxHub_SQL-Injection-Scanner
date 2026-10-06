# SQL Injection Scanner — Local/Lab Edition

A defensive SQL injection assessment tool for **authorized local/lab applications only**.

## Safety boundary

The scanner intentionally refuses:
- public IP addresses
- arbitrary remote hostnames
- non-localhost URLs
- URLs without an HTTP/HTTPS scheme

Allowed hosts:
- `localhost`
- `127.0.0.1`
- `::1`

Use it against applications you own or explicitly have permission to test, such as DVWA running locally.

## Requirements

- Python 3.10+
- `requests`

Install:

```bash
python -m pip install -r requirements.txt
```

## Usage

Show help:

```bash
python scanner.py --help
```

Scan a local URL:

```bash
python scanner.py --url "http://127.0.0.1:8080/search.php?q=test"
```

Example with conservative controls:

```bash
python scanner.py \
  --url "http://127.0.0.1:8080/search.php?q=test" \
  --workers 2 \
  --rate 2 \
  --timeout 8 \
  --format both
```

### POST form

```bash
python scanner.py \
  --url "http://127.0.0.1:8080/login.php" \
  --method POST \
  --data "username=test&password=test"
```

### Important

This is a **detector**, not an exploitation framework. It uses a small set of non-destructive test values and reports indicators rather than attempting database extraction.

Reports are written to `reports/`.

## Detection approach

1. Capture a baseline response.
2. Test a parameter with a small set of quote/error indicators.
3. Test paired boolean conditions.
4. Compare status, normalized body length, hashes, and selected SQL-error signatures.
5. Assign a confidence level.
6. Save all observations.

Time-based probing is deliberately omitted from this local training version because timing tests can be noisy and unnecessarily expensive. It can be added later for controlled lab use.

## Disclaimer

Only scan systems you own or are explicitly authorized to test.
