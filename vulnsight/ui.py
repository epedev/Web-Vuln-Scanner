"""VulnSight terminal UI — distinctive CLI presentation with NO_COLOR support."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from typing import Any, TextIO

from vulnsight import __version__

# Deep teal + amber (security lab look; avoids generic purple / neon-green defaults)
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_TEAL = "\033[38;5;37m"
_TEAL_BRIGHT = "\033[38;5;44m"
_AMBER = "\033[38;5;214m"
_RED = "\033[38;5;167m"
_GREEN = "\033[38;5;108m"
_SLATE = "\033[38;5;245m"
_WHITE = "\033[38;5;255m"


@dataclass
class Theme:
    enabled: bool

    def s(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}{_RESET}"

    def bold(self, text: str) -> str:
        return self.s(_BOLD, text)

    def dim(self, text: str) -> str:
        return self.s(_DIM, text)

    def teal(self, text: str) -> str:
        return self.s(_TEAL, text)

    def teal_bright(self, text: str) -> str:
        return self.s(_TEAL_BRIGHT, text)

    def amber(self, text: str) -> str:
        return self.s(_AMBER, text)

    def red(self, text: str) -> str:
        return self.s(_RED, text)

    def green(self, text: str) -> str:
        return self.s(_GREEN, text)

    def slate(self, text: str) -> str:
        return self.s(_SLATE, text)

    def white(self, text: str) -> str:
        return self.s(_WHITE, text)


def color_enabled(*, force: bool | None = None, stream: TextIO | None = None) -> bool:
    if force is False:
        return False
    if force is True:
        return True
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("VULNSIGHT_NO_COLOR") in {"1", "true", "yes"}:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    out = stream or sys.stdout
    return bool(getattr(out, "isatty", lambda: False)())


def get_theme(*, no_color: bool = False) -> Theme:
    return Theme(enabled=color_enabled(force=False if no_color else None))


BANNER_COMPACT = [
    "╔══════════════════════════════════════════╗",
    "║   V U L N S I G H T                      ║",
    "║   see the weakness · prove the risk      ║",
    "╚══════════════════════════════════════════╝",
]


class Console:
    """Styled stdout/stderr writer for VulnSight commands."""

    def __init__(
        self,
        *,
        no_color: bool = False,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        self.out = out or sys.stdout
        self.err = err or sys.stderr
        self.theme = get_theme(no_color=no_color)
        self.width = min(shutil.get_terminal_size((88, 24)).columns, 88)

    def print(self, text: str = "", *, file: TextIO | None = None) -> None:
        stream = file or self.out
        print(text, file=stream, flush=True)

    def rule(self, title: str = "", *, char: str = "─") -> None:
        t = self.theme
        if title:
            label = f" {title} "
            pad = max(0, self.width - len(label))
            left = pad // 2
            right = pad - left
            self.print(t.teal(f"{char * left}{label}{char * right}"))
        else:
            self.print(t.dim(char * self.width))

    def banner(self, *, subtitle: str | None = None) -> None:
        t = self.theme
        self.print()
        for i, line in enumerate(BANNER_COMPACT):
            if i == 1:
                self.print(t.bold(t.teal_bright(line)))
            else:
                self.print(t.teal(line))
        tag = subtitle or "authorized web vulnerability scanner"
        self.print(t.amber(f"  v{__version__}  ·  {tag}"))
        self.print(t.dim("  " + "─" * min(42, self.width - 2)))
        self.print()

    def panel(self, title: str, rows: list[tuple[str, str]]) -> None:
        t = self.theme
        content_widths = [len(title)]
        rendered_rows: list[str] = []
        for key, value in rows:
            line = f"{key}: {value}"
            content_widths.append(len(line))
            rendered_rows.append(line)
        inner = min(max(max(content_widths) + 2, 36), self.width - 4)
        self.print(t.teal(f"┌{'─' * (inner + 2)}┐"))
        title_pad = max(0, inner - len(title))
        self.print(f"│ {t.bold(t.teal(title))}{' ' * title_pad} │")
        self.print(t.dim(f"├{'─' * (inner + 2)}┤"))
        for line in rendered_rows:
            if len(line) > inner:
                line = line[: inner - 1] + "…"
            self.print(f"│ {line.ljust(inner)} │")
        self.print(t.teal(f"└{'─' * (inner + 2)}┘"))

    def status_ok(self, message: str) -> None:
        t = self.theme
        self.print(f"  {t.green('✔')}  {message}")

    def status_fail(self, message: str) -> None:
        t = self.theme
        self.print(f"  {t.red('✖')}  {message}", file=self.err)

    def status_info(self, message: str) -> None:
        t = self.theme
        self.print(f"  {t.teal('▸')}  {message}")

    def status_warn(self, message: str) -> None:
        t = self.theme
        self.print(f"  {t.amber('!')}  {message}", file=self.err)

    def module_line(self, status: str, name: str, findings: int, detail: str = "") -> None:
        t = self.theme
        glyph = {
            "completed": t.green("●"),
            "completed_with_warnings": t.amber("●"),
            "failed": t.red("●"),
            "skipped": t.slate("○"),
            "unsupported": t.slate("○"),
        }.get(status, t.slate("·"))
        label = t.bold(name.ljust(18))
        find = t.white(str(findings).rjust(3))
        st = {
            "completed": t.green(status),
            "completed_with_warnings": t.amber(status),
            "failed": t.red(status),
            "skipped": t.slate(status),
        }.get(status, t.dim(status))
        extra = f"  {t.dim(detail)}" if detail else ""
        self.print(f"  {glyph} {label} {st}  findings={find}{extra}")

    def finding_meter(self, confirmed: int, suspected: int, total: int) -> None:
        t = self.theme
        width = 28
        if total <= 0:
            bar = t.dim("░" * width)
        else:
            c = max(0, min(width, round(width * confirmed / total)))
            s = max(0, min(width - c, round(width * suspected / total)))
            r = width - c - s
            bar = t.red("█" * c) + t.amber("█" * s) + t.dim("░" * r)
        self.print(f"  intensity  [{bar}]")
        self.print(
            f"  {t.red(str(confirmed) + ' confirmed')}  ·  "
            f"{t.amber(str(suspected) + ' suspected')}  ·  "
            f"{t.white(str(total) + ' total')}"
        )

    def render_scan_header(
        self,
        *,
        target: str,
        scope: str,
        modules: list[str],
        output: str,
        project: str | None = None,
        authorized_by: str | None = None,
        codebase: str | None = None,
    ) -> None:
        self.banner(subtitle="recon → detect → score → report")
        rows = [
            ("target", target),
            ("scope", scope),
            ("modules", ", ".join(modules)),
            ("output", output),
        ]
        if project:
            rows.insert(0, ("project", project))
        if authorized_by:
            rows.append(("auth by", authorized_by))
        if codebase:
            rows.append(("codebase", codebase))
        self.panel("SCAN BRIEF", rows)
        self.print()
        self.status_info("Engaging modules — evidence over assumptions")
        self.print()

    def render_scan_result(self, result: Any) -> None:
        t = self.theme
        confirmed = suspected = 0
        for f in result.findings:
            status = (f.get("verification_status") or "").lower()
            if status == "confirmed":
                confirmed += 1
            elif status in {"probable", "candidate"}:
                suspected += 1

        self.rule("RESULTS")
        self.print(t.bold(f"  Target  {result.target}"))
        self.print(t.dim(f"  Scope   {result.scope_mode}"))
        self.print()
        self.finding_meter(confirmed, suspected, len(result.findings))
        self.print()

        if result.incomplete:
            self.status_warn("Coverage PARTIAL — some modules failed or were skipped")
            self.print()

        self.print(t.bold(t.teal("  MODULES")))
        for run in result.module_runs:
            detail = ""
            if run.errors:
                detail = run.errors[0][:100]
            elif run.detail:
                detail = run.detail[:100]
            self.module_line(run.status, run.name, run.findings_count, detail)

        self.print()
        self.print(t.bold(t.teal("  ARTIFACTS")))
        for kind, path in sorted(result.report_paths.items()):
            if kind in {"json", "html", "findings", "pdf", "md", "markdown"}:
                self.print(f"  {t.amber('→')}  {t.slate(kind.ljust(8))} {path}")

        self.print()
        if result.exit_code == 0:
            self.status_ok("Scan pipeline finished")
        else:
            self.status_warn(
                "Scan finished with module failures (findings from OK modules kept)"
            )
        self.rule()
        self.print()

    def render_doctor_header(self) -> None:
        self.banner(subtitle="environment readiness check")
        self.status_info("Python tooling · module layout · lab presence")
        self.print()

    def render_doctor_footer(self, ok: bool) -> None:
        self.print()
        if ok:
            self.status_ok("RESULT: ready — you can run vulnsight scan")
        else:
            self.status_fail("RESULT: not ready — fix FAIL items above")
        self.rule()
        self.print()

    def hint(self, message: str) -> None:
        t = self.theme
        for line in message.splitlines():
            self.print(t.dim(f"     {line}"), file=self.err)
