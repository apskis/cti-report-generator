"""Action model and YAML-backed store with append-only history."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ruamel.yaml import YAML

from carryover.week import Week

Status = Literal["open", "in_progress", "blocked", "complete"]

_VALID_STATUSES: set[str] = {"open", "in_progress", "blocked", "complete"}

_DEFAULT_PATH = Path("data/actions.yaml")


@dataclass
class HistoryEntry:
    week: str
    status: str
    note: str = ""


@dataclass
class Action:
    id: str
    title: str
    description: str
    owner: str
    first_raised_week: str
    target_week: str
    status: Status
    closure_note: str = ""
    history: list[HistoryEntry] = field(default_factory=list)

    def age_weeks(self, report_week: Week) -> int:
        """Compute age in weeks relative to report_week. Never stored."""
        return report_week - Week.parse(self.first_raised_week)

    def is_overdue(self, report_week: Week) -> bool:
        """True if not complete and target_week is before report_week."""
        if self.status == "complete":
            return False
        return Week.parse(self.target_week) < report_week


class ActionStore:
    """YAML-backed store for actions. History is append-only."""

    def __init__(self, path: Path | str | None = None):
        self._path = Path(path) if path else _DEFAULT_PATH
        self._yaml = YAML()
        self._yaml.default_flow_style = False
        self._yaml.preserve_quotes = True
        self._actions: list[Action] = []
        self._next_seq: int = 1
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        with open(self._path, "r", encoding="utf-8") as f:
            data = self._yaml.load(f)
        if not data:
            return
        for item in data:
            history = [
                HistoryEntry(week=h["week"], status=h["status"], note=h.get("note", ""))
                for h in (item.get("history") or [])
            ]
            action = Action(
                id=item["id"],
                title=item["title"],
                description=item["description"],
                owner=item["owner"],
                first_raised_week=item["first_raised_week"],
                target_week=item["target_week"],
                status=item["status"],
                closure_note=item.get("closure_note", ""),
                history=history,
            )
            self._actions.append(action)
            seq = self._parse_seq(action.id)
            if seq >= self._next_seq:
                self._next_seq = seq + 1

    @staticmethod
    def _parse_seq(action_id: str) -> int:
        # ACT-2026-001 -> 1
        parts = action_id.split("-")
        return int(parts[-1])

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = []
        for a in self._actions:
            item = {
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "owner": a.owner,
                "first_raised_week": a.first_raised_week,
                "target_week": a.target_week,
                "status": a.status,
                "closure_note": a.closure_note,
                "history": [
                    {"week": h.week, "status": h.status, "note": h.note}
                    for h in a.history
                ],
            }
            data.append(item)
        with open(self._path, "w", encoding="utf-8") as f:
            self._yaml.dump(data, f)

    def _next_id(self) -> str:
        # Extract year from first_raised_week of most recent, or use current year
        year = Week.current().year
        action_id = f"ACT-{year}-{self._next_seq:03d}"
        self._next_seq += 1
        return action_id

    def add(
        self,
        title: str,
        description: str,
        owner: str,
        first_raised_week: str,
        target_week: str,
        status: Status = "open",
    ) -> Action:
        """Add a new action. Validates week formats and appends initial history."""
        # Validate weeks parse correctly
        frw = Week.parse(first_raised_week)
        Week.parse(target_week)

        action_id = f"ACT-{frw.year}-{self._next_seq:03d}"
        self._next_seq += 1

        history = [HistoryEntry(week=first_raised_week, status=status, note="Action raised")]

        action = Action(
            id=action_id,
            title=title,
            description=description,
            owner=owner,
            first_raised_week=first_raised_week,
            target_week=target_week,
            status=status,
            history=history,
        )
        self._actions.append(action)
        self._save()
        return action

    def get(self, action_id: str) -> Action | None:
        for a in self._actions:
            if a.id == action_id:
                return a
        return None

    def update(
        self,
        action_id: str,
        week: str,
        status: Status | None = None,
        note: str = "",
        closure_note: str | None = None,
    ) -> Action:
        """Update an action's status. Appends to history (never edits).

        Raises ValueError if:
        - Action not found
        - Completing without a closure_note
        - Completion week is before first_raised_week
        """
        action = self.get(action_id)
        if action is None:
            raise ValueError(f"Action {action_id} not found")

        # Validate week
        update_week = Week.parse(week)

        new_status = status or action.status

        if new_status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}")

        # Completion rules
        if new_status == "complete":
            final_note = closure_note or note
            if not final_note:
                raise ValueError("Completion requires a closure_note")
            if update_week < Week.parse(action.first_raised_week):
                raise ValueError(
                    f"Completion week {week} cannot be earlier than "
                    f"first_raised_week {action.first_raised_week}"
                )
            action.closure_note = final_note

        action.status = new_status
        action.history.append(HistoryEntry(week=week, status=new_status, note=note or closure_note or ""))
        self._save()
        return action

    def list_actions(
        self,
        status_filter: Status | None = None,
        overdue_only: bool = False,
        report_week: Week | None = None,
    ) -> list[Action]:
        """List actions with optional filters."""
        rw = report_week or Week.current()
        result = []
        for a in self._actions:
            if status_filter and a.status != status_filter:
                continue
            if overdue_only and not a.is_overdue(rw):
                continue
            result.append(a)
        return result

    def actions_for_table(self, report_week: Week) -> list[Action]:
        """Return actions to include in the carryover table for a given week.

        Include: every action not complete, plus any completed in the report week.
        Exclude: anything completed in an earlier week.
        Sort: overdue first, then descending age, then id.
        """
        included = []
        for a in self._actions:
            if a.status != "complete":
                included.append(a)
            else:
                # Include if completed in report_week
                completion_week = self._completion_week(a)
                if completion_week and completion_week == report_week:
                    included.append(a)

        # Sort: overdue first, then descending age, then id
        def sort_key(action: Action) -> tuple:
            overdue = action.is_overdue(report_week)
            age = action.age_weeks(report_week)
            return (not overdue, -age, action.id)

        included.sort(key=sort_key)
        return included

    @staticmethod
    def _completion_week(action: Action) -> Week | None:
        """Find the week an action was completed (last 'complete' history entry)."""
        for entry in reversed(action.history):
            if entry.status == "complete":
                return Week.parse(entry.week)
        return None

    @property
    def all_actions(self) -> list[Action]:
        return list(self._actions)
