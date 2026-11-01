"""D1-04: the SPI ports, their in-memory fakes and the spy writer."""

from __future__ import annotations

import socket

import pytest

from sto.adapters.fake.notifier import FakeNotifier
from sto.adapters.fake.scm import FakeScm
from sto.adapters.fake.spy import SpyWriter
from sto.adapters.fake.tickets import FakeTicketSource
from sto.adapters.ports import (
    BoardRef,
    CheckSpec,
    CommitIntent,
    DispatchSpec,
    GateMessage,
    IntakeQuery,
    MergeMethod,
    MergeState,
    Notifier,
    PatchRef,
    PrRef,
    PrSpec,
    RawWebhook,
    RepoRef,
    ScmProvider,
    StaleHeadError,
    StatusIntent,
    Ticket,
    TicketRef,
    TicketSource,
)
from sto.domain.errors import PermanentError

REPO = RepoRef("acme", "app")
TREF = TicketRef("fake", "T-1")


def _scm() -> tuple[FakeScm, SpyWriter]:
    spy = SpyWriter()
    scm = FakeScm(spy)
    scm.seed_branch(REPO, "main", "sha0")
    return scm, spy


def test_fakes_satisfy_the_ports() -> None:
    spy = SpyWriter()
    assert isinstance(FakeTicketSource(spy), TicketSource)
    assert isinstance(FakeScm(spy), ScmProvider)
    assert isinstance(FakeNotifier(spy), Notifier)


def test_fakes_need_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    scm, _ = _scm()
    scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k1")
    FakeNotifier(SpyWriter()).send(GateMessage("g1", "s", "digest"), "k2")


def test_spy_records_every_write_in_order_and_filters() -> None:
    spy = SpyWriter()
    t = FakeTicketSource(spy)
    t.add_ticket(Ticket(TREF, "title", "body", "open"))
    t.get(TREF)  # a read is not a write
    t.comment(TREF, "hi", "k1")
    t.transition(TREF, StatusIntent.IN_REVIEW, "k2")
    assert [c.method for c in spy.calls] == ["comment", "transition"]
    assert spy.calls_for("comment")[0].args["body"] == "hi"
    assert spy.calls[0].port == "ticket_source"
    assert spy.calls[1].key == "k2"
    spy.clear()
    assert spy.calls == ()


def test_results_are_marked_simulated() -> None:
    scm, _ = _scm()
    n = FakeNotifier(SpyWriter())
    t = FakeTicketSource(SpyWriter())
    t.add_ticket(Ticket(TREF, "t", "b", "open"))
    receipts = [
        t.comment(TREF, "x", "k1"),
        n.send(GateMessage("g", "s", "d"), "k2"),
        scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k3"),
    ]
    assert all(r.simulated for r in receipts)


def test_idempotent_write_returns_same_receipt_but_spy_sees_both_calls() -> None:
    t_spy = SpyWriter()
    t = FakeTicketSource(t_spy)
    t.add_ticket(Ticket(TREF, "t", "b", "open"))
    r1 = t.comment(TREF, "x", "same")
    r2 = t.comment(TREF, "x", "same")
    assert r1 == r2
    assert len(t.comments(TREF)) == 1
    assert len(t_spy.calls_for("comment")) == 2
    assert [c.replayed for c in t_spy.calls_for("comment")] == [False, True]


def test_ticket_search_paginates_and_parse_event() -> None:
    t = FakeTicketSource(SpyWriter())
    for i in range(5):
        t.add_ticket(Ticket(TicketRef("fake", f"T-{i}"), f"t{i}", "", "open"))
    p1 = t.search(IntakeQuery(), None, page_size=2)
    assert len(p1.items) == 2
    assert p1.next_cursor is not None
    p2 = t.search(IntakeQuery(), p1.next_cursor, page_size=10)
    assert len(p2.items) == 3
    assert p2.next_cursor is None
    changes = t.parse_event(RawWebhook({}, b'{"ticket": "T-1"}'))
    assert [c.ref.key for c in changes] == ["T-1"]
    assert t.current_sprint(BoardRef("b")) is None


def test_commit_intent_is_known_before_ref_moves() -> None:
    scm, _ = _scm()
    intent = scm.create_commit(REPO, PatchRef("p1"), "sha0")
    assert isinstance(intent, CommitIntent)
    assert intent.sha
    assert intent.parent == "sha0"
    assert scm.head(REPO, "main") == "sha0"  # not moved yet
    receipt = scm.move_ref(REPO, "main", intent, expected_head="sha0")
    assert receipt.simulated
    assert scm.head(REPO, "main") == intent.sha


def test_move_ref_refuses_a_stale_expected_head_without_moving() -> None:
    scm, spy = _scm()
    intent = scm.create_commit(REPO, PatchRef("p1"), "sha0")
    with pytest.raises(StaleHeadError):
        scm.move_ref(REPO, "main", intent, expected_head="other")
    assert scm.head(REPO, "main") == "sha0"
    assert isinstance(StaleHeadError("x"), PermanentError)
    assert spy.calls_for("move_ref")[0].args["expected_head"] == "other"


def test_merge_is_async_and_checks_expected_sha() -> None:
    scm, _ = _scm()
    pr = PrRef(REPO, 1)
    scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k")
    scm.set_pr_head(pr, "h1")
    with pytest.raises(StaleHeadError):
        scm.request_merge(pr, "wrong", MergeMethod.SQUASH, "m0")
    handle = scm.request_merge(pr, "h1", MergeMethod.SQUASH, "m1")
    assert scm.poll_merge(handle).state is MergeState.PENDING
    scm.complete_merge(handle, merge_sha="m-sha")
    done = scm.poll_merge(handle)
    assert done.state is MergeState.MERGED
    assert done.merge_sha == "m-sha"
    # idempotent: same key, same handle
    assert scm.request_merge(pr, "h1", MergeMethod.SQUASH, "m1") == handle


def test_dequeue_requires_matching_head_and_stops_the_merge() -> None:
    scm, _ = _scm()
    pr = PrRef(REPO, 1)
    scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k")
    scm.set_pr_head(pr, "h1")
    handle = scm.request_merge(pr, "h1", MergeMethod.MERGE, "m1")
    with pytest.raises(StaleHeadError):
        scm.dequeue(pr, "nope")
    assert scm.dequeue(pr, "h1").simulated
    assert scm.poll_merge(handle).state is MergeState.DEQUEUED


def test_pr_lifecycle_and_other_writes_are_recorded() -> None:
    scm, spy = _scm()
    pr_receipt = scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k")
    again = scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k-other")
    assert pr_receipt.external_id == again.external_id  # finds or creates, keyed by branch
    pr = PrRef(REPO, 1)
    scm.mark_ready(pr, "k2")
    assert scm.pr_state(pr) == "ready"
    scm.set_pr_head(pr, "h1")
    upd = scm.merge_base_into(pr, "h1", "k3")
    assert upd.sha != "h1"
    assert upd.parent_head == "h1"
    with pytest.raises(StaleHeadError):
        scm.merge_base_into(pr, "stale", "k4")
    scm.promote(REPO, "h1", "sto-approved/x", "k5")
    scm.publish_check(CheckSpec(REPO, "h1", "sto", "success"), "k6")
    assert [c.name for c in scm.checks(REPO, "h1")] == ["sto"]
    scm.trigger_workflow(REPO, DispatchSpec("release.yml", "main", {}), "k7")
    scm.open_revert_pr("m-sha", "k8")
    scm.close_pr(pr, "k9")
    assert scm.pr_state(pr) == "closed"
    assert scm.ci_trust(REPO).trusted is True
    methods = {c.method for c in spy.calls}
    assert methods >= {
        "ensure_draft_pr", "mark_ready", "merge_base_into", "promote", "publish_check",
        "trigger_workflow", "open_revert_pr", "close_pr",
    }  # fmt: skip
    assert scm.snapshot(REPO, "h1").uri
    assert scm.parse_event(RawWebhook({}, b"{}")) == []


def test_notifier_send_update_and_parse_action() -> None:
    spy = SpyWriter()
    n = FakeNotifier(spy)
    r = n.send(GateMessage("g1", "summary", "d1"), "k")
    r2 = n.update(r, GateMessage("g1", "closed", "d1"))
    assert r2.external_id == r.external_id
    assert r2.simulated
    assert n.messages()[0].summary == "closed"
    assert n.parse_action(RawWebhook({}, b"")) is None
    assert [c.method for c in spy.calls] == ["send", "update"]
