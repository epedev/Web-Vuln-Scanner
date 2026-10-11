# XSS Lab Fixture

Intentionally vulnerable local application for authorized testing of the XSS module.

## Start

```bash
python fixtures/vulnerable_app/app.py
```

Listens on `http://127.0.0.1:5001` only.

## Routes

| Route | Behavior |
|-------|----------|
| `/reflect?q=` | **Vulnerable** reflected HTML body (unencoded) |
| `/encoded?q=` | **Safe** HTML-encoded body |
| `/attr?q=` | **Vulnerable** double-quoted attribute |
| `/js?q=` | **Vulnerable** JavaScript single-quoted string |
| `/url?q=` | Encoded `href` (should not be confirmed XSS from marker alone) |
| `/inert?q=` | Reflection inside HTML comment (inert) |
| `/comment` + `/comments` | **Vulnerable** stored XSS (POST body → unencoded list) |
| `/multi?a=&b=` | Mixed: `a` unencoded, `b` encoded |
| `/redirect-external` | Out-of-scope redirect target |

Do not deploy this app publicly.
