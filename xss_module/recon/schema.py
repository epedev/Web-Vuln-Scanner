"""Canonical crawl_map.json schema produced by the Recon module.

This schema is the integration contract for XSS and future detection modules.
Established as the project baseline because the repository had no prior schema.
"""

from __future__ import annotations

from typing import Any

CRAWL_MAP_VERSION = "1.0"

# Example shape (documented; not enforced as JSON Schema library dependency):
#
# {
#   "version": "1.0",
#   "target": "http://127.0.0.1:5001",
#   "generated_at": "2026-10-11T18:00:00+00:00",
#   "pages": [
#     {
#       "url": "http://127.0.0.1:5001/search",
#       "method": "GET",
#       "status": 200,
#       "content_type": "text/html",
#       "params": [
#         {"name": "q", "value": "test", "source": "query", "input_type": "text"}
#       ],
#       "forms": [],
#       "links": [],
#       "renders_from": []
#     }
#   ],
#   "forms": [
#     {
#       "action": "http://127.0.0.1:5001/comment",
#       "method": "POST",
#       "enctype": "application/x-www-form-urlencoded",
#       "fields": [
#         {"name": "body", "value": "", "input_type": "text", "required": false},
#         {"name": "submit", "value": "Post", "input_type": "submit", "required": false}
#       ],
#       "source_page": "http://127.0.0.1:5001/comment",
#       "renders_to": ["http://127.0.0.1:5001/comments"]
#     }
#   ],
#   "endpoints": [
#     {
#       "url": "http://127.0.0.1:5001/search",
#       "method": "GET",
#       "params": [{"name": "q", "value": "", "source": "query", "input_type": "text"}]
#     }
#   ]
# }


REQUIRED_TOP_LEVEL = {"version", "target", "pages"}


def validate_crawl_map(data: Any) -> list[str]:
    """Return a list of validation errors (empty means OK)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["crawl_map root must be an object"]

    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            errors.append(f"missing required top-level field: {key}")

    if "pages" in data and not isinstance(data["pages"], list):
        errors.append("pages must be a list")
    if "forms" in data and data["forms"] is not None and not isinstance(data["forms"], list):
        errors.append("forms must be a list when present")
    if "endpoints" in data and data["endpoints"] is not None and not isinstance(
        data["endpoints"], list
    ):
        errors.append("endpoints must be a list when present")

    for i, page in enumerate(data.get("pages") or []):
        if not isinstance(page, dict):
            errors.append(f"pages[{i}] must be an object")
            continue
        if "url" not in page:
            errors.append(f"pages[{i}].url is required")
        if "method" in page and str(page["method"]).upper() not in {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
        }:
            errors.append(f"pages[{i}].method is invalid")

    for i, form in enumerate(data.get("forms") or []):
        if not isinstance(form, dict):
            errors.append(f"forms[{i}] must be an object")
            continue
        if "action" not in form:
            errors.append(f"forms[{i}].action is required")
        if "fields" in form and not isinstance(form["fields"], list):
            errors.append(f"forms[{i}].fields must be a list")

    return errors
