#!/usr/bin/env bash
# Generate a VulnSight demo report from packaged fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/reporting_module"
python report_module.py \
  --xss fixtures/findings_xss.json \
  --sqli fixtures/findings_sqli.json \
  --misconfig fixtures/findings_misconfig.json \
  --target http://127.0.0.1:5001 \
  --origin http://127.0.0.1:5001 \
  --format html --format json \
  -o reports/
echo "Open: $ROOT/reporting_module/reports/vulnsight_report.html"
