"""Terminal presentation primitives with Rich and a safe plain-text fallback."""

from __future__ import annotations

from contextlib import nullcontext
import re
import sys
from typing import Iterable

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
except ImportError:  # The CLI remains usable before requirements are installed.
    Console = None
    Panel = None
    Progress = None
    Table = None
    box = None


SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "dim",
}


class TerminalUI:
    def __init__(self, quiet: bool = False, no_color: bool = False) -> None:
        self.quiet = quiet
        self.no_color = no_color
        self.ansi = not no_color and sys.stdout.isatty()
        self.console = Console(no_color=no_color) if Console else None

    @property
    def rich(self) -> bool:
        return self.console is not None

    def print(self, value: object = "") -> None:
        if self.console:
            self.console.print(value)
        else:
            print(value)

    def panel(self, title: str, body: object, style: str = "cyan", markup: bool = False) -> None:
        if self.console and Panel:
            if isinstance(body, str) and not markup:
                from rich.text import Text

                body = Text(body)
            self.print(Panel(body, title=title, border_style=style, padding=(1, 2)))
        else:
            plain_body = re.sub(r"\[/?[^\]]+\]", "", str(body))
            if self.ansi:
                self.print(f"\n\033[96m╭─ {title} {'─' * max(2, 54 - len(title))}╮\033[0m")
                self.print(f"\033[96m│\033[0m {plain_body.replace(chr(10), chr(10) + chr(27) + '[96m│' + chr(27) + '[0m ')}")
                self.print("\033[96m╰" + "─" * 62 + "╯\033[0m")
            else:
                self.print(f"\n=== {title} ===\n{plain_body}\n")

    def table(self, title: str, columns: Iterable[str], rows: Iterable[Iterable[object]]) -> None:
        rows = list(rows)
        if self.console and Table:
            table = Table(title=title, header_style="bold cyan", border_style="bright_blue", expand=True, show_lines=False)
            for column in columns:
                table.add_column(column, overflow="fold")
            for row in rows:
                table.add_row(*(str(value) for value in row))
            self.print(table)
            return
        if self.ansi:
            self.print(f"\033[1;96m┌─ {title}\033[0m")
            self.print("\033[96m│\033[0m " + "  │  ".join(columns))
            self.print("\033[96m├" + "─" * 62 + "┤\033[0m")
            for row in rows:
                self.print("\033[96m│\033[0m " + "  │  ".join(str(value) for value in row))
            self.print("\033[96m└" + "─" * 62 + "┘\033[0m")
        else:
            self.print(title)
            self.print(" | ".join(columns))
        for row in rows:
            if not self.ansi:
                self.print(" | ".join(str(value) for value in row))

    def menu(self, options: Iterable[tuple[str, str, str]]) -> None:
        """Render the command deck once, or when the user explicitly asks for it."""

        options = list(options)
        if self.console and Table:
            table = Table(
                title="COMMANDS  //  h for help",
                title_style="bold bright_cyan",
                box=box.SIMPLE if box else None,
                border_style="bright_blue",
                show_header=False,
                expand=False,
                padding=(0, 1),
            )
            table.add_column("KEY", style="bold bright_cyan", width=9, justify="left", no_wrap=True)
            table.add_column("MODULE", style="bold white", width=14, no_wrap=True)
            table.add_column("DESCRIPTION", style="dim white", overflow="fold")
            for key, label, description in options:
                table.add_row(key, label, description)
            self.print(table)
            return
        self.print("\nCOMMANDS  //  h for help")
        for key, label, description in options:
            self.print(f"  {key:>2}  {label:<24} {description}")

    def status_line(self, value: str) -> None:
        """Print one compact status line suitable for the persistent prompt."""

        if self.console:
            from rich.text import Text

            self.print(Text(value, style="dim cyan"))
        else:
            self.print(value)

    def severity(self, value: object) -> object:
        text = getattr(value, "value", value)
        if self.console:
            from rich.text import Text

            return Text(str(text).upper(), style=SEVERITY_STYLES.get(str(text).lower(), "white"))
        text = str(text).upper()
        if self.ansi:
            color = {"CRITICAL": "41", "HIGH": "31", "MEDIUM": "33", "LOW": "36"}.get(text, "2")
            return f"\033[{color}m{text}\033[0m"
        return text

    def progress_context(self):
        if not self.console or not Progress:
            return nullcontext(None)
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            transient=False,
        )

    def prompt(self, message: str, default: str = "") -> str:
        if self.console:
            from rich.prompt import Prompt

            return Prompt.ask(message) if not default else Prompt.ask(message, default=default)
        suffix = f" [{default}]" if default else ""
        return input(f"{message}{suffix}: ").strip() or default

    def pause(self) -> None:
        if self.console and not self.quiet:
            self.prompt("Press Enter to return to the menu", default="")

