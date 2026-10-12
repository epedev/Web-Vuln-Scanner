"""SQL injection detection package."""

from sqli.detector import check_local_target, inspect_response

__all__ = ["check_local_target", "inspect_response"]
