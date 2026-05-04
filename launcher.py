#!/usr/bin/env python3
"""
Friendly launcher for Automation Station.

Detects whether a .env config exists. If yes, runs the pipeline.
If no, walks the user through an interactive setup, saves config,
then runs the pipeline.
"""

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()

CONFIG_SEARCH_PATHS = [
    Path.cwd() / ".env",
    Path.home() / ".config" / "automation-station" / "config.env",
    Path("/etc/automation-station/config.env"),
]

DEFAULT_NEW_CONFIG_PATH = Path.cwd() / ".env"

REQUIRED_VARS = [
    ("SUBNET",             "Subnet to scan (CIDR)",     "192.168.1.0/24"),
    ("NETBOX_URL",         "NetBox URL",                "https://netbox.local"),
    ("NETBOX_TOKEN",       "NetBox API token",          None),
    ("SNMP_COMMUNITY",     "SNMP community string",     "public"),
    ("SNMP_VERSION",       "SNMP version (1 or 2c)",    "2c"),
    ("SNMP_TARGET_SUBNET", "SNMP target subnet",        "192.168.1.0/24"),
]

OPTIONAL_VARS = [
    ("CONFIDENCE_THRESHOLD",  "Confidence threshold for NetBox push (0-100)", "75"),
    ("MAIL_REPORT_THRESHOLD", "Score below which devices get flagged",        "40"),
]


def find_config():
    for path in CONFIG_SEARCH_PATHS:
        if path.exists():
            return path
    return None


def interactive_setup():
    console.print(Panel.fit(
        "[bold]Automation Station Setup[/bold]\n\n"
        "No configuration found. Let's create one.\n"
        "Press Enter to accept defaults shown in brackets.",
        border_style="cyan",
    ))

    values = {}

    console.print("\n[bold cyan]Required settings[/bold cyan]")
    for key, prompt_text, default in REQUIRED_VARS:
        is_secret = "TOKEN" in key or "PASSWORD" in key
        value = Prompt.ask(f"  {prompt_text}", default=default, password=is_secret)
        if not value:
            console.print(f"  [red]✘ {key} is required[/red]")
            return None
        values[key] = value

    console.print("\n[bold cyan]Optional settings[/bold cyan]")
    for key, prompt_text, default in OPTIONAL_VARS:
        values[key] = Prompt.ask(f"  {prompt_text}", default=default)

    console.print()
    save_path = Path(Prompt.ask("Save config to", default=str(DEFAULT_NEW_CONFIG_PATH))).expanduser()

    if save_path.exists():
        if not Confirm.ask(f"[yellow]{save_path} exists. Overwrite?[/yellow]", default=False):
            console.print("[red]Aborted.[/red]")
            return None

    save_path.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Automation Station configuration", ""]
    for key, _, _ in REQUIRED_VARS:
        lines.append(f"{key}={values[key]}")
    lines.append("")
    for key, _, _ in OPTIONAL_VARS:
        lines.append(f"{key}={values[key]}")
    lines.append("")

    save_path.write_text("\n".join(lines))
    save_path.chmod(0o600)

    console.print(f"\n[green]✔ Config saved to {save_path}[/green]")
    console.print("[dim]Permissions set to 600 to protect the API token.[/dim]\n")
    return save_path


def run_pipeline():
    from main import main as run_main
    run_main()


def main():
    config_path = find_config()

    if config_path:
        console.print(f"[green]✔ Using config:[/green] {config_path}")
        from dotenv import load_dotenv
        load_dotenv(config_path)
    else:
        config_path = interactive_setup()
        if not config_path:
            sys.exit(1)
        from dotenv import load_dotenv
        load_dotenv(config_path)

    console.print("\n[bold cyan]Starting pipeline...[/bold cyan]\n")
    try:
        run_pipeline()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]✘ Pipeline failed:[/red] {e}")
        if "--debug" in sys.argv:
            raise
        console.print("[dim]Run with --debug to see the full traceback.[/dim]")
        sys.exit(1)

    console.print("\n[green]✔ Done.[/green]")
    try:
        input("\nPress Enter to close...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()