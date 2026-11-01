"""D1-04: the SPI fakes must be as strict as the real service (PLAN 6.3, 6.4, 10.1)."""

from __future__ import annotations

import json
import socket

import pytest

from sto.adapters.fake.notifier import FakeNotifier
from sto.adapters.fake.scm import FakeScm
from sto.adapters.fake.spy import SpyWriter
from sto.adapters.fake.tickets import FakeTicketSource
from sto.adapters.ports import (
    BoardRef,
    ChangeKind,
    CheckSpec,
    CommitIntent,
    DispatchSpec,
    GateMessage,
    IdempotencyKeyReuseError,
    IntakeQuery,
    MalformedWebhookError,
    MergeMethod,
    MergeState,
    Notifier,
    PatchRef,
    PrRef,
    PrSpec,
    RawWebhook,
    RefusedError,
    RepoRef,
    ScmProvider,
    StaleHeadError,
    StatusIntent,
    Ticket,
    TicketRef,
    TicketSource,
    UnknownRefError,
)
from sto.domain.errors import FailureClass, PermanentError, StoError
from sto.domain.models import DecisionKind, Receipt

REPO = RepoRef("acme", "app")
TREF = TicketRef("fake", "T-1")
PR = PrRef(REPO, 1)
SPEC = PrSpec(REPO, "sto/x", "main", "t", "b")


def _raw(**body: object) -> RawWebhook:
    return RawWebhook({}, json.dumps(body).encode())


def _tickets(spy: SpyWriter | None = None, **kw: int) -> tuple[FakeTicketSource, SpyWriter]:
    spy = spy or SpyWriter()
    t = FakeTicketSource(spy, **kw)
    t.add_ticket(Ticket(TREF, "title", "body", "open"))
    return t, spy


def _scm() -> tuple[FakeScm, SpyWriter]:
    spy = SpyWriter()
    scm = FakeScm(spy)
    scm.seed_branch(REPO, "main", "sha0")
    scm.seed_branch(REPO, "sto/x", "sha0")
    return scm, spy


def _ready_pr(scm: FakeScm) -> str:
    """A ready PR on sto/x, one commit ahead of main. Returns its head."""
    scm.ensure_draft_pr(SPEC, "pr-k")
    head = _advance(scm, "sto/x", "p1")
    scm.mark_ready(PR, "ready-k")
    return head


def _advance(scm: FakeScm, branch: str, patch: str) -> str:
    old = scm.head(REPO, branch)
    intent = scm.create_commit(REPO, PatchRef(patch), old)
    scm.move_ref(REPO, branch, intent, expected_head=old)
    return intent.sha


_STATIC_TICKETS: TicketSource = FakeTicketSource()
_STATIC_SCM: ScmProvider = FakeScm()
_STATIC_NOTIFIER: Notifier = FakeNotifier()


def test_fakes_satisfy_the_ports() -> None:
    assert isinstance(_STATIC_TICKETS, TicketSource)
    assert isinstance(_STATIC_SCM, ScmProvider)
    assert isinstance(_STATIC_NOTIFIER, Notifier)


def test_fakes_need_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    _scm()[0].ensure_draft_pr(SPEC, "k1")
    FakeNotifier().send(GateMessage("g1", "s", "digest"), "k2")
    _tickets()[0].comment(TREF, "x", "k3")


def test_spy_records_every_write_in_order_and_filters() -> None:
    t, spy = _tickets()
    t.get(TREF)  # a read is not a write
    t.comment(TREF, "hi", "k1")
    t.transition(TREF, StatusIntent.IN_REVIEW, "k2")
    assert [c.method for c in spy.calls] == ["comment", "transition"]
    assert spy.calls_for("comment")[0].args["body"] == "hi"
    assert spy.calls[0].port == "ticket_source"
    assert spy.calls[1].key == "k2"


def test_spy_marks_refused_writes_so_applied_writes_can_be_counted() -> None:
    scm, spy = _scm()
    intent = scm.create_commit(REPO, PatchRef("p"), "sha0")
    with pytest.raises(StaleHeadError):
        scm.move_ref(REPO, "main", intent, expected_head="elsewhere")
    scm.move_ref(REPO, "main", intent, expected_head="sha0")
    moves = spy.calls_for("move_ref")
    assert [c.error for c in moves] == ["StaleHeadError", None]
    assert len(spy.applied("move_ref")) == 1


def test_idempotent_replay_is_flagged_and_not_applied_twice() -> None:
    t, spy = _tickets()
    r1 = t.comment(TREF, "x", "same")
    r2 = t.comment(TREF, "x", "same")
    assert r1 == r2
    assert len(t.comments(TREF)) == 1
    assert [c.replayed for c in spy.calls_for("comment")] == [False, True]
    assert len(spy.applied("comment")) == 1


def test_key_reuse_with_different_arguments_is_refused() -> None:
    t, spy = _tickets()
    t.add_ticket(Ticket(TicketRef("fake", "T-2"), "t", "b", "open"))
    t.comment(TREF, "one", "K")
    with pytest.raises(IdempotencyKeyReuseError):
        t.comment(TicketRef("fake", "T-2"), "two", "K")
    with pytest.raises(IdempotencyKeyReuseError):
        t.comment(TREF, "two", "K")
    assert len(t.comments(TREF)) == 1
    assert spy.calls_for("comment")[-1].error == "IdempotencyKeyReuseError"
    other, _ = _tickets(spy)  # the ledger is per fake: the same key on another fake is fine
    other.comment(TREF, "y", "K")
    n = FakeNotifier()
    a = n.send(GateMessage("g1", "s", "d"), "K")
    assert n.send(GateMessage("g1", "s", "d"), "K") == a
    with pytest.raises(IdempotencyKeyReuseError):
        n.send(GateMessage("g2", "s", "d"), "K")


def test_ticket_search_paginates_with_the_constructor_page_size() -> None:
    t, _ = _tickets(page_size=2)
    for i in range(2):
        t.add_ticket(Ticket(TicketRef("fake", f"T-{i + 10}"), "t", "", "open"))
    p1 = t.search(IntakeQuery(), None)
    assert (len(p1.items), p1.next_cursor is not None) == (2, True)
    p2 = t.search(IntakeQuery(), p1.next_cursor)
    assert (len(p2.items), p2.next_cursor) == (1, None)
    with pytest.raises(RefusedError):
        t.search(IntakeQuery(), "not-a-cursor")


def test_ticket_writes_to_a_missing_ticket_raise_a_domain_error() -> None:
    t, spy = _tickets()
    ghost = TicketRef("fake", "NOPE")
    for call in (
        lambda: t.get(ghost),
        lambda: t.comment(ghost, "x", "k"),
        lambda: t.transition(ghost, StatusIntent.DONE, "k2"),
    ):
        with pytest.raises(UnknownRefError):
            call()
    assert spy.applied() == ()
    assert t.current_sprint(BoardRef("b")) is None


def test_ticket_revision_ignores_comments_and_transitions_but_not_content() -> None:
    t, _ = _tickets()
    before = t.get(TREF).revision
    t.comment(TREF, "chatter", "k1")
    t.transition(TREF, StatusIntent.DONE, "k2")
    assert t.get(TREF).revision == before

    def rev(title: str = "t", ac: str = "ac", risk: str = "high", status: str = "open") -> str:
        return Ticket(
            TREF, title, "b", status, acceptance_criteria=ac, route_fields=(("r", risk),)
        ).revision

    assert rev() == rev(" t ", status="closed")
    assert len({rev(), rev(ac="ac2"), rev(risk="low")}) == 3


def test_ticket_parse_event_delivers_changes_and_refuses_garbage_cleanly() -> None:
    t, _ = _tickets()
    changes = t.parse_event(_raw(changes=[{"kind": "ticket", "ticket": "T-1"}]))
    assert [(c.kind, c.ticket) for c in changes] == [(ChangeKind.TICKET, TREF)]
    assert t.parse_event(RawWebhook({}, b"")) == []
    for bad in (b"not json", b"[]", b'{"changes": [{"kind": "nope"}]}', b'{"changes": 3}'):
        with pytest.raises(MalformedWebhookError):
            t.parse_event(RawWebhook({}, bad))


def test_move_ref_refuses_a_stale_expected_head_without_moving() -> None:
    scm, spy = _scm()
    intent = scm.create_commit(REPO, PatchRef("p1"), "sha0")
    with pytest.raises(StaleHeadError) as info:
        scm.move_ref(REPO, "main", intent, expected_head="other")
    err = info.value  # not PermanentError (that means BLOCKED); stale has its own edge (6.4)
    assert isinstance(err, StoError)
    assert not isinstance(err, PermanentError)
    assert err.failure_class is not FailureClass.PERMANENT
    assert not err.retryable
    assert scm.head(REPO, "main") == "sha0"  # the SHA was known before the ref moved
    assert spy.calls_for("move_ref")[0].args["expected_head"] == "other"
    assert intent.parent == "sha0"
    assert scm.move_ref(REPO, "main", intent, expected_head="sha0").simulated
    assert scm.head(REPO, "main") == intent.sha


def test_move_ref_is_never_a_force_push() -> None:
    scm, _ = _scm()
    first = _advance(scm, "main", "p1")
    # a commit made on the old parent is not a fast-forward of the new head
    sideways = scm.create_commit(REPO, PatchRef("p2"), "sha0")
    with pytest.raises(RefusedError):
        scm.move_ref(REPO, "main", sideways, expected_head=first)
    assert scm.head(REPO, "main") == first
    # an unregistered commit cannot be pointed at either
    forged = CommitIntent("f" * 40, first, PatchRef("p3"))
    with pytest.raises(RefusedError):
        scm.move_ref(REPO, "main", forged, expected_head=first)
    with pytest.raises(UnknownRefError):
        scm.create_commit(REPO, PatchRef("p4"), "no-such-parent")
    with pytest.raises(UnknownRefError):
        scm.move_ref(REPO, "no-branch", sideways, expected_head="x")


def test_draft_pr_needs_existing_branches() -> None:
    scm, spy = _scm()
    with pytest.raises(UnknownRefError):
        scm.ensure_draft_pr(PrSpec(REPO, "ghost", "main", "t", "b"), "k")
    with pytest.raises(UnknownRefError):
        scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "ghost-base", "t", "b"), "k2")
    assert spy.applied() == ()


def test_merge_base_into_moves_the_branch_and_replays_the_original_result() -> None:
    scm, _ = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    head = scm.head(REPO, "sto/x")
    first = scm.merge_base_into(PR, head, "upd")
    assert first.sha != head
    assert first.parent_head == head
    assert first.receipt is not None
    assert first.receipt.simulated
    assert scm.pr_head(PR) == first.sha
    assert scm.head(REPO, "sto/x") == first.sha
    # the new commit is real: it can be a parent
    scm.create_commit(REPO, PatchRef("next"), first.sha)
    # a replay after the head moved on returns the original result, not the current head
    _advance(scm, "sto/x", "later")
    assert scm.merge_base_into(PR, head, "upd") == first
    with pytest.raises(StaleHeadError):
        scm.merge_base_into(PR, head, "upd2")


def test_merge_base_into_can_report_a_conflict_without_moving() -> None:
    scm, spy = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    scm.set_update_conflict(PR, True)
    res = scm.merge_base_into(PR, "sha0", "upd")
    assert res.conflict
    assert res.receipt is None
    assert res.sha == "sha0"
    assert scm.pr_head(PR) == "sha0"
    assert len(spy.applied("merge_base_into")) == 1


def test_merge_is_async_and_checks_expected_sha() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    with pytest.raises(StaleHeadError):
        scm.request_merge(PR, "wrong", MergeMethod.SQUASH, "m0")
    with pytest.raises(StaleHeadError):
        scm.request_merge(PR, "", MergeMethod.SQUASH, "m00")
    handle = scm.request_merge(PR, head, MergeMethod.SQUASH, "m1")
    assert scm.poll_merge(handle).state is MergeState.PENDING
    assert scm.pr_state(PR) == "ready"
    scm.complete_merge(handle, merge_sha="m-sha")
    done = scm.poll_merge(handle)
    assert done.state is MergeState.MERGED
    assert done.merge_sha == "m-sha"
    assert done.receipt is not None
    assert done.receipt.simulated
    assert scm.pr_state(PR) == "merged"
    assert scm.request_merge(PR, head, MergeMethod.SQUASH, "m1") == handle
    with pytest.raises(IdempotencyKeyReuseError):
        scm.request_merge(PR, "another", MergeMethod.SQUASH, "m1")


def test_merge_refuses_draft_and_closed_prs() -> None:
    scm, spy = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    head = scm.head(REPO, "sto/x")
    with pytest.raises(RefusedError):
        scm.request_merge(PR, head, MergeMethod.MERGE, "m1")  # still a draft
    scm.mark_ready(PR, "r")
    scm.close_pr(PR, "c")
    with pytest.raises(RefusedError):
        scm.request_merge(PR, head, MergeMethod.MERGE, "m2")
    assert spy.applied("request_merge") == ()


def test_a_head_moved_while_pending_never_reaches_merged() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    handle = scm.request_merge(PR, head, MergeMethod.SQUASH, "m1")
    _advance(scm, "sto/x", "late-push")
    failed = scm.poll_merge(handle)
    assert failed.state is MergeState.FAILED
    assert failed.receipt is not None
    assert failed.receipt.simulated
    with pytest.raises(RefusedError):
        scm.complete_merge(handle, merge_sha="m-sha")
    assert scm.pr_state(PR) == "ready"
    h2 = scm.request_merge(PR, scm.pr_head(PR), MergeMethod.MERGE, "m2")
    scm.fail_merge(h2)  # the test control
    assert scm.poll_merge(h2).state is MergeState.FAILED


def test_a_new_request_on_a_pr_already_merged_at_that_sha_is_success() -> None:
    scm, spy = _scm()
    head = _ready_pr(scm)
    handle = scm.request_merge(PR, head, MergeMethod.SQUASH, "m1")
    scm.complete_merge(handle, merge_sha="m-sha")
    again = scm.request_merge(PR, head, MergeMethod.SQUASH, "m-new-key")
    assert scm.poll_merge(again).state is MergeState.MERGED
    assert len(spy.applied("request_merge")) == 2  # both calls succeeded, only one merge exists
    with pytest.raises(RefusedError):
        scm.request_merge(PR, "other-sha", MergeMethod.SQUASH, "m-other")


def test_dequeue_needs_a_matching_head_and_a_pending_merge() -> None:
    scm, spy = _scm()
    head = _ready_pr(scm)
    with pytest.raises(RefusedError):
        scm.dequeue(PR, head)  # nothing queued
    handle = scm.request_merge(PR, head, MergeMethod.MERGE, "m1")
    with pytest.raises(StaleHeadError):
        scm.dequeue(PR, "nope")
    assert scm.dequeue(PR, head).simulated
    assert scm.poll_merge(handle).state is MergeState.DEQUEUED
    with pytest.raises(RefusedError):
        scm.complete_merge(handle, merge_sha="m-sha")  # a dequeued merge cannot be revived
    with pytest.raises(RefusedError):
        scm.dequeue(PR, head)  # already dequeued
    assert len(spy.applied("dequeue")) == 1
    scm2, _ = _scm()
    h2 = scm2.request_merge(PR, _ready_pr(scm2), MergeMethod.MERGE, "m1")
    scm2.complete_merge(h2, merge_sha="m")
    with pytest.raises(RefusedError):
        scm2.dequeue(PR, scm2.pr_head(PR))  # the merge already landed


def test_ensure_draft_pr_finds_an_open_pr_but_not_a_closed_one() -> None:
    scm, _ = _scm()
    first = scm.ensure_draft_pr(SPEC, "k")
    again = scm.ensure_draft_pr(SPEC, "k-other")
    assert first.external_id == again.external_id  # finds or creates, keyed by branch
    scm.close_pr(PR, "c")
    fresh = scm.ensure_draft_pr(SPEC, "k-third")
    assert fresh.external_id != first.external_id
    assert scm.pr_state(PrRef(REPO, 2)) == "draft"


def test_mark_ready_and_close_respect_pr_state() -> None:
    scm, _ = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    scm.mark_ready(PR, "r1")
    scm.close_pr(PR, "c1")
    with pytest.raises(RefusedError):
        scm.mark_ready(PR, "r2")  # a closed PR is not reopened
    assert scm.pr_state(PR) == "closed"
    scm.close_pr(PR, "c2")  # closing twice is fine


def test_closing_a_pr_cancels_its_pending_merge() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    handle = scm.request_merge(PR, head, MergeMethod.MERGE, "m1")
    scm.close_pr(PR, "c")
    assert scm.poll_merge(handle).state is MergeState.DEQUEUED


def test_promote_never_overwrites_a_branch() -> None:
    scm, spy = _scm()
    head = _advance(scm, "sto/x", "p1")
    scm.promote(REPO, head, "sto-approved/x", "k1")
    assert scm.head(REPO, "sto-approved/x") == head
    with pytest.raises(RefusedError):
        scm.promote(REPO, "sha0", "sto-approved/x", "k2")  # exists at another sha
    with pytest.raises(RefusedError):
        scm.promote(REPO, head, "main", "k3")
    with pytest.raises(UnknownRefError):
        scm.promote(REPO, "no-such-sha", "sto-approved/y", "k4")
    assert scm.head(REPO, "main") == "sha0"
    assert len(spy.applied("promote")) == 1


def test_republished_check_keeps_only_the_latest_result() -> None:
    scm, _ = _scm()
    scm.publish_check(CheckSpec(REPO, "sha0", "sto", "pending"), "k1")
    scm.publish_check(CheckSpec(REPO, "sha0", "sto", "success"), "k2")
    scm.publish_check(CheckSpec(REPO, "sha0", "other", "failure"), "k3")
    assert [(c.name, c.conclusion) for c in scm.checks(REPO, "sha0")] == [
        ("sto", "success"),
        ("other", "failure"),
    ]
    with pytest.raises(UnknownRefError):
        scm.publish_check(CheckSpec(REPO, "no-such-sha", "sto", "success"), "k4")


def test_snapshot_workflow_and_revert_need_known_targets() -> None:
    scm, _ = _scm()
    assert scm.snapshot(REPO, "sha0").uri
    with pytest.raises(UnknownRefError):
        scm.snapshot(REPO, "nope")
    with pytest.raises(UnknownRefError):
        scm.open_revert_pr("never-merged", "k")
    head = _ready_pr(scm)
    scm.complete_merge(scm.request_merge(PR, head, MergeMethod.MERGE, "m"), merge_sha="m-sha")
    first = scm.open_revert_pr("m-sha", "rk1")
    # a declared revert and the engine's implicit one open one PR (PLAN 6.3)
    assert scm.open_revert_pr("m-sha", "rk2").external_id == first.external_id
    assert scm.trigger_workflow(REPO, DispatchSpec("release.yml", "main"), "w").simulated


def test_scm_parse_event_delivers_changes() -> None:
    scm, _ = _scm()
    push = {"kind": "push", "repo": "acme/app", "branch": "main", "sha": "abc"}
    pr = {"kind": "pr", "repo": "acme/app", "pr": 3}
    got = scm.parse_event(_raw(changes=[push, pr]))
    assert [c.kind for c in got] == [ChangeKind.PUSH, ChangeKind.PR]
    assert (got[0].repo, got[1].pr) == (REPO, PrRef(REPO, 3))
    assert scm.parse_event(RawWebhook({}, b"")) == []


def test_every_write_path_returns_a_simulated_receipt() -> None:
    scm, _ = _scm()
    t, _ = _tickets()
    n = FakeNotifier()
    scm.ensure_draft_pr(SPEC, "k")
    updated = scm.merge_base_into(PR, "sha0", "u1")
    ready = scm.mark_ready(PR, "r")
    handle = scm.request_merge(PR, updated.sha, MergeMethod.MERGE, "m1")
    scm.complete_merge(handle, merge_sha="m-sha")
    sent = n.send(GateMessage("g", "s", "d"), "n1")
    move = scm.create_commit(REPO, PatchRef("z"), "sha0")
    receipts: list[Receipt | None] = [
        t.comment(TREF, "x", "t1"),
        t.transition(TREF, StatusIntent.DONE, "t2"),
        sent,
        ready,
        n.update(sent, GateMessage("g", "s2", "d")),
        scm.ensure_draft_pr(PrSpec(REPO, "main", "main", "t", "b"), "s1"),
        scm.close_pr(PrRef(REPO, 2), "s3"),
        scm.move_ref(REPO, "main", move, expected_head="sha0"),
        scm.promote(REPO, updated.sha, "sto-approved/x", "s4"),
        scm.open_revert_pr("m-sha", "s5"),
        scm.trigger_workflow(REPO, DispatchSpec("w.yml", "main"), "s6"),
        scm.publish_check(CheckSpec(REPO, updated.sha, "sto", "success"), "s7"),
        updated.receipt,
        scm.poll_merge(handle).receipt,
    ]
    assert all(r is not None and r.simulated for r in receipts)


def test_read_back_can_be_switched_off_to_model_accepted_but_not_applied() -> None:
    t, _ = _tickets()
    scm, _ = _scm()
    n = FakeNotifier()
    for fake in (t, scm, n):
        fake.read_back_verified = False
    receipts = [
        t.comment(TREF, "x", "k"),
        scm.ensure_draft_pr(SPEC, "k"),
        n.send(GateMessage("g", "s", "d"), "k"),
    ]
    assert not any(r.read_back_verified for r in receipts)
    t.read_back_verified = True
    assert t.comment(TREF, "y", "k2").read_back_verified


def test_notifier_update_returns_a_fresh_simulated_receipt_for_known_messages_only() -> None:
    spy = SpyWriter()
    n = FakeNotifier(spy)
    msg = GateMessage("g1", "summary", "d1", attention=("a",), deep_link="https://x/g1")
    r = n.send(msg, "k")
    r2 = n.update(r, GateMessage("g1", "closed", "d1"))
    assert r2.external_id == r.external_id
    assert r2.simulated
    assert n.messages()[0].summary == "closed"
    forged = Receipt("forged", "", True)
    with pytest.raises(UnknownRefError):
        n.update(forged, msg)
    # a caller cannot launder simulated=False through update either
    assert n.update(Receipt(r.external_id, "", True, simulated=False), msg).simulated
    assert [c.error for c in spy.calls_for("update")] == [None, "UnknownRefError", None]


def test_notifier_parse_action_delivers_decisions_and_refuses_garbage() -> None:
    n = FakeNotifier()
    assert n.parse_action(RawWebhook({}, b"")) is None
    req = n.parse_action(
        _raw(gate_id="g1", kind="approve", actor="u1", subject_digest="dig", comment="ok")
    )
    assert req is not None
    assert req.kind is DecisionKind.APPROVE
    assert (req.gate_id, req.actor, req.subject_digest, req.comment) == ("g1", "u1", "dig", "ok")
    for bad in (b"nope", b"[]", json.dumps({"gate_id": "g", "kind": "maybe"}).encode()):
        with pytest.raises(MalformedWebhookError):
            n.parse_action(RawWebhook({}, bad))
