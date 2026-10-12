# Crawler module

Produces `crawl_map.json` for VulnSight `xss_module`.

## Discovery

1. Start at `--seed` within `--origin`
2. Fetch HTML pages (bounded by `--max-pages`)
3. Extract query parameters from URLs
4. Extract links (`<a href>`) — enqueue only in-scope same-origin URLs
5. Extract forms (`action`, `method`, fields)
6. Heuristic `renders_to` from same-page links whose path suggests listing/view pages (`comment`, `guest`, `message`, …) for stored-XSS correlation

## Integration with XSS

```
Crawler → crawl_map.json → xss_module.py → findings_xss.json → reporting_module
```

## Limitations

- HTML-focused; does not execute JavaScript / SPA routes
- `renders_to` is heuristic, not application truth
- No automatic authentication beyond supplied cookies/headers
- Does not submit forms during crawl (read-only discovery)
