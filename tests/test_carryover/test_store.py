"""Tests for ActionStore: append-only history, completion rules, table inclusion."""

import pytest
from pathlib import Path
from carryover.store import ActionStore, Action
from carryover.week import Week


@pytest.fixture
def tmp_store(tmp_path):
    """Provide a store backed by a temp file."""
    return ActionStore(path=tmp_path / "actions.yaml")


@pytest.fixture
def populated_store(tmp_store):
    """Store with a few actions for testing."""
    tmp_store.add(
        title="Patch servers",
        description="Patch all servers",
        owner="Alice",
        first_raised_week="2026-W23",
        target_week="2026-W30",
    )
    tmp_store.add(
        title="Enable MFA",
        description="Enable MFA everywhere",
        owner="Bob",
        first_raised_week="2026-W25",
        target_week="2026-W32",
    )
    return tmp_store


class TestAddAndHistory:
    def test_add_creates_action_with_history(self, tmp_store):
        action = tmp_store.add(
            title="Test action",
            description="Desc",
            owner="Owner",
            first_raised_week="2026-W23",
            target_week="2026-W30",
        )
        assert action.id == "ACT-2026-001"
        assert len(action.history) == 1
        assert action.history[0].week == "2026-W23"
        assert action.history[0].status == "open"

    def test_sequential_ids(self, tmp_store):
        a1 = tmp_store.add("A", "d", "o", "2026-W23", "2026-W30")
        a2 = tmp_store.add("B", "d", "o", "2026-W24", "2026-W31")
        assert a1.id == "ACT-2026-001"
        assert a2.id == "ACT-2026-002"

    def test_persistence_roundtrip(self, tmp_path):
        path = tmp_path / "test.yaml"
        store1 = ActionStore(path=path)
        store1.add("Test", "Desc", "Owner", "2026-W23", "2026-W30")

        store2 = ActionStore(path=path)
        assert len(store2.all_actions) == 1
        assert store2.all_actions[0].title == "Test"
        assert len(store2.all_actions[0].history) == 1


class TestUpdate:
    def test_update_appends_history(self, populated_store):
        populated_store.update("ACT-2026-001", week="2026-W25", status="in_progress", note="Started")
        action = populated_store.get("ACT-2026-001")
        assert action.status == "in_progress"
        assert len(action.history) == 2
        assert action.history[1].week == "2026-W25"
        assert action.history[1].note == "Started"

    def test_update_nonexistent_raises(self, populated_store):
        with pytest.raises(ValueError, match="not found"):
            populated_store.update("ACT-9999-999", week="2026-W25")

    def test_history_never_shrinks(self, populated_store):
        populated_store.update("ACT-2026-001", week="2026-W25", status="in_progress", note="a")
        populated_store.update("ACT-2026-001", week="2026-W26", status="blocked", note="b")
        populated_store.update("ACT-2026-001", week="2026-W27", status="in_progress", note="c")
        action = populated_store.get("ACT-2026-001")
        assert len(action.history) == 4  # initial + 3 updates


class TestCompletion:
    def test_complete_requires_closure_note(self, populated_store):
        with pytest.raises(ValueError, match="closure_note"):
            populated_store.update("ACT-2026-001", week="2026-W30", status="complete")

    def test_complete_with_closure_note_succeeds(self, populated_store):
        action = populated_store.update(
            "ACT-2026-001",
            week="2026-W30",
            status="complete",
            closure_note="Patched all servers on 2026-07-20",
        )
        assert action.status == "complete"
        assert action.closure_note == "Patched all servers on 2026-07-20"

    def test_complete_before_first_raised_raises(self, populated_store):
        with pytest.raises(ValueError, match="cannot be earlier"):
            populated_store.update(
                "ACT-2026-001",
                week="2026-W20",  # Before W23
                status="complete",
                closure_note="Done",
            )


class TestOverdue:
    def test_overdue_when_past_target(self, populated_store):
        action = populated_store.get("ACT-2026-001")  # target W30
        assert action.is_overdue(Week(2026, 31))

    def test_not_overdue_at_target_week(self, populated_store):
        action = populated_store.get("ACT-2026-001")  # target W30
        assert not action.is_overdue(Week(2026, 30))

    def test_not_overdue_before_target(self, populated_store):
        action = populated_store.get("ACT-2026-001")  # target W30
        assert not action.is_overdue(Week(2026, 28))

    def test_complete_action_not_overdue(self, populated_store):
        populated_store.update(
            "ACT-2026-001", week="2026-W30", status="complete",
            closure_note="Done",
        )
        action = populated_store.get("ACT-2026-001")
        assert not action.is_overdue(Week(2026, 35))


class TestTableInclusion:
    def test_open_actions_included(self, populated_store):
        actions = populated_store.actions_for_table(Week(2026, 30))
        ids = [a.id for a in actions]
        assert "ACT-2026-001" in ids
        assert "ACT-2026-002" in ids

    def test_completed_this_week_included(self, populated_store):
        populated_store.update(
            "ACT-2026-001", week="2026-W30", status="complete",
            closure_note="Done",
        )
        actions = populated_store.actions_for_table(Week(2026, 30))
        ids = [a.id for a in actions]
        assert "ACT-2026-001" in ids

    def test_completed_earlier_week_excluded(self, populated_store):
        populated_store.update(
            "ACT-2026-001", week="2026-W28", status="complete",
            closure_note="Done",
        )
        actions = populated_store.actions_for_table(Week(2026, 30))
        ids = [a.id for a in actions]
        assert "ACT-2026-001" not in ids

    def test_sort_overdue_first(self, populated_store):
        # ACT-001 target W30, ACT-002 target W32. Report week W31.
        # ACT-001 is overdue, ACT-002 is not.
        actions = populated_store.actions_for_table(Week(2026, 31))
        assert actions[0].id == "ACT-2026-001"  # overdue comes first

    def test_sort_by_age_descending(self, tmp_store):
        tmp_store.add("Old", "d", "o", "2026-W20", "2026-W40")
        tmp_store.add("New", "d", "o", "2026-W28", "2026-W40")
        actions = tmp_store.actions_for_table(Week(2026, 30))
        # Older action first (more age)
        assert actions[0].title == "Old"
        assert actions[1].title == "New"


class TestAgeCalculation:
    def test_age_same_year(self, populated_store):
        action = populated_store.get("ACT-2026-001")  # raised W23
        assert action.age_weeks(Week(2026, 31)) == 8

    def test_age_cross_year(self, tmp_store):
        tmp_store.add("Old", "d", "o", "2025-W50", "2026-W10")
        action = tmp_store.get("ACT-2025-001")
        # 2025-W50 to 2026-W03: should be positive
        age = action.age_weeks(Week(2026, 3))
        assert age == 5
