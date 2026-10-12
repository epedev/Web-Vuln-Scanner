# Module guide

## Recon (`Crawler/`)

```bash
cd Crawler
python crawler_module.py --seed http://127.0.0.1:5001/ \
  --origin http://127.0.0.1:5001 --allow-loopback -o crawl_map.json
```

## XSS (`xss_module/`)

```bash
cd xss_module
python xss_module.py --crawl-map ../reports/crawl_map.json \
  --origin http://127.0.0.1:5001 --allow-loopback \
  --active-verify --metachar-probes --enable-stored-xss -o findings_xss.json
```

Browser verification is optional (`--browser-verify` + Playwright). Without it, findings remain candidate/probable when execution is not proven.

## SQLi / command injection (`sqli_&_command_module/`)

Programmatic:

```python
from sqli.detector import check_local_target
from command_injection.detector import check_local_target as cmd
check_local_target("http://127.0.0.1:5001")
cmd("http://127.0.0.1:5001")
```

## Access control (`access_control_module/`)

Uses lab accounts `alice`/`alice123` and `bob`/`bobpass` against `/profile/<id>` and `/admin`.

## Reporting (`reporting_module/`)

```bash
cd reporting_module
python report_module.py --xss fixtures/findings_xss.json \
  --format html --format json -o reports/
```
