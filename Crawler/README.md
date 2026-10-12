# Crawler

VulnSight same-origin crawler that produces `crawl_map.json` **v1.0** for the XSS module.

## Output contract

Matches `xss_module` input schema:

- `version`, `target`, `pages[]`
- `forms[]` with `fields`, `source_page`, `renders_to` (heuristic for stored XSS)
- `endpoints[]` with query/form parameters

## Setup

```bash
cd Crawler
python -m pip install -r requirements.txt
```

## Run

```bash
python crawler_module.py \
  --seed http://127.0.0.1:5001/ \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  -o crawl_map.json -v
```

Then scan with XSS:

```bash
cd ../xss_module   # or ../ if using local layout
python xss_module.py \
  --crawl-map ../Crawler/crawl_map.json \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  --active-verify --metachar-probes \
  -o findings_xss.json
```

## Programmatic API

```python
from crawler_module import run_crawler_module

crawl_map = run_crawler_module(
    seed_url="http://127.0.0.1:5001/",
    allowed_origins=["http://127.0.0.1:5001"],
    allow_loopback=True,
    output_path="crawl_map.json",
)
```

## Safety

- Explicit `--origin` required (seed alone is not authorization)
- Loopback/private networks blocked unless opted in
- Does not follow out-of-scope links or redirects
- Does not expand scope from discovered hosts
- Recognizable User-Agent: `WebVulnScanner/0.1 (+authorized-lab; crawler)`

## Tests

```bash
pytest -q
```
