
import pytest

from gateway.infra.repository import AgentScopeError, Repository, ScopedRepository


def test_for_agent_returns_scoped_repository(tmp_path) -> None:
    repository = Repository(tmp_path / "gateway.sqlite")

    scoped = repository.for_agent("agent-a")

    assert isinstance(scoped, ScopedRepository)
    assert scoped._agent_id == "agent-a"


def test_empty_agent_scope_is_rejected(tmp_path) -> None:
    repository = Repository(tmp_path / "gateway.sqlite")

    with pytest.raises(AgentScopeError):
        repository.for_agent("")


def test_foreign_keys_are_enabled(tmp_path) -> None:
    repository = Repository(tmp_path / "gateway.sqlite")

    enabled = repository._connection.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0]

    assert enabled == 1


def test_tasks_are_scoped_by_agent(tmp_path) -> None:
    repository = Repository(tmp_path / "gateway.sqlite")
    scoped = repository.for_agent("agent-a")

    rows = scoped.list_tasks()

    assert all(row["agent_id"] == "agent-a" for row in rows)


def test_approval_lookup_cannot_cross_agent_scope(tmp_path) -> None:
    repository = Repository(tmp_path / "gateway.sqlite")

    agent_a = repository.for_agent("agent-a")

    assert agent_a.get_approval("approval-owned-by-agent-b") is None
