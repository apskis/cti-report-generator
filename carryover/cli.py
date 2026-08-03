"""CLI for the carryover action tracker."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from carryover.store import ActionStore, Status
from carryover.table import render_docx, render_markdown
from carryover.week import Week

app = typer.Typer(name="carryover", help="Track recommended actions across weekly CTI reports.")


def _get_store() -> ActionStore:
    return ActionStore()


@app.command()
def add(
    title: str = typer.Option(..., prompt=True, help="Short imperative phrase"),
    description: str = typer.Option(..., prompt=True, help="One or two sentences for the report"),
    owner: str = typer.Option(..., prompt=True, help="Action owner"),
    first_raised_week: str = typer.Option(..., "--raised", prompt="First raised week (YYYY-Www)", help="Week action was first raised"),
    target_week: str = typer.Option(..., "--target", prompt="Target week (YYYY-Www)", help="Target completion week"),
    status: str = typer.Option("open", help="Initial status"),
):
    """Add a new recommended action."""
    store = _get_store()
    action = store.add(
        title=title,
        description=description,
        owner=owner,
        first_raised_week=first_raised_week,
        target_week=target_week,
        status=status,
    )
    typer.echo(f"Created {action.id}: {action.title}")


@app.command()
def update(
    action_id: str = typer.Argument(..., help="Action ID (e.g. ACT-2026-001)"),
    status: Optional[str] = typer.Option(None, "--status", help="New status"),
    week: str = typer.Option(..., "--week", help="Week of this update (YYYY-Www)"),
    note: str = typer.Option("", "--note", help="Update note"),
    closure_note: Optional[str] = typer.Option(None, "--closure-note", help="Required when completing"),
):
    """Update an action's status (appends to history)."""
    store = _get_store()
    try:
        action = store.update(
            action_id=action_id,
            week=week,
            status=status,
            note=note,
            closure_note=closure_note,
        )
        typer.echo(f"Updated {action.id} → {action.status}")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command("list")
def list_actions(
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
    overdue: bool = typer.Option(False, "--overdue", help="Show only overdue actions"),
    week: Optional[str] = typer.Option(None, "--week", help="Reference week for overdue (default: current)"),
):
    """List actions with optional filters."""
    store = _get_store()
    rw = Week.parse(week) if week else Week.current()
    actions = store.list_actions(status_filter=status, overdue_only=overdue, report_week=rw)

    if not actions:
        typer.echo("No actions found.")
        return

    for a in actions:
        age = a.age_weeks(rw)
        overdue_marker = " [OVERDUE]" if a.is_overdue(rw) else ""
        typer.echo(f"{a.id}  {a.status:<12} {age:>2}wk  {a.title}{overdue_marker}")


@app.command()
def table(
    week: str = typer.Option(..., "--week", help="Report week (YYYY-Www)"),
    format: str = typer.Option("docx", "--format", help="Output format: docx or md"),
    out: Optional[str] = typer.Option(None, "--out", help="Output path (default: auto-named)"),
):
    """Generate the carryover table for a report week."""
    store = _get_store()
    report_week = Week.parse(week)
    actions = store.actions_for_table(report_week)

    if format == "md":
        md = render_markdown(actions, report_week)
        if out:
            Path(out).write_text(md, encoding="utf-8")
            typer.echo(f"Written to {out}")
        else:
            typer.echo(md)
    elif format == "docx":
        output_path = Path(out) if out else Path(f"reports/Carryover_Table_{week}.docx")
        render_docx(actions, report_week, output_path)
        typer.echo(f"Written to {output_path}")
    else:
        typer.echo(f"Unknown format: {format}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
