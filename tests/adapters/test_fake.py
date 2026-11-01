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
    MergeReason,
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
from sto.domain.errors import PermanentError, TransientError
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
    scm.seed_branch(REPO, "sto/x", "sha1", parent="sha0")  # one commit ahead of main
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
    spy.clear()
    assert spy.calls == ()


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
    for i in range(4):
        t.add_ticket(Ticket(TicketRef("fake", f"T-{i + 10}"), f"t{i}", "", "open"))
    p1 = t.search(IntakeQuery(), None)
    assert len(p1.items) == 2
    assert p1.next_cursor is not None
    p2 = t.search(IntakeQuery(), p1.next_cursor)
    assert len(p2.items) == 2
    p3 = t.search(IntakeQuery(), p2.next_cursor)
    assert len(p3.items) == 1
    assert p3.next_cursor is None
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
    assert isinstance(info.value, PermanentError)  # fails closed; D1-07 maps it for pr.merge only
    assert not info.value.retryable
    assert isinstance(intent, CommitIntent)
    assert intent.sha
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


def test_pr_head_follows_the_branch_head() -> None:
    scm, _ = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    assert scm.pr_head(PR) == "sha1"
    head = _advance(scm, "sto/x", "p1")
    assert scm.pr_head(PR) == head


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
    base = _advance(scm, "main", "base1")
    head = scm.head(REPO, "sto/x")
    first = scm.merge_base_into(PR, head, "upd")
    assert first.sha != head
    assert first.parent_head == head
    assert first.receipt is not None
    assert first.receipt.simulated
    assert scm.pr_head(PR) == first.sha
    assert scm.head(REPO, "sto/x") == first.sha
    assert scm.snapshot(REPO, first.sha).uri  # the new commit is real
    scm.create_commit(REPO, PatchRef("next"), first.sha)
    # a replay after the head moved on returns the original result, not the current head
    _advance(scm, "sto/x", "later")
    assert scm.merge_base_into(PR, head, "upd") == first
    with pytest.raises(StaleHeadError):
        scm.merge_base_into(PR, head, "upd2")
    # nothing left to merge: no new commit, and not counted as a state change
    tip = scm.head(REPO, "sto/x")
    again = scm.merge_base_into(PR, tip, "upd3")
    assert (again.sha, again.conflict) == (tip, False)
    assert scm.head(REPO, "sto/x") == tip
    assert base != tip
    assert scm.head(REPO, "main") == base
    assert scm.spy.calls_for("merge_base_into")[-1].noop


def test_merge_base_into_refuses_a_closed_pr() -> None:
    scm, _ = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    scm.close_pr(PR, "c")
    _advance(scm, "main", "base1")
    with pytest.raises(RefusedError):
        scm.merge_base_into(PR, scm.head(REPO, "sto/x"), "upd")


def test_merge_base_into_can_report_a_conflict_without_moving() -> None:
    scm, spy = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    _advance(scm, "main", "base1")
    scm.set_update_conflict(PR, True)
    res = scm.merge_base_into(PR, "sha1", "upd")
    assert res.conflict
    assert res.receipt is None
    assert (res.sha, res.parent_head) == ("sha1", "sha1")
    assert scm.pr_head(PR) == "sha1"
    assert spy.applied("merge_base_into") == ()  # a conflict changes nothing


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
    assert failed.reason is MergeReason.STALE
    assert failed.receipt is not None
    assert failed.receipt.simulated
    with pytest.raises(RefusedError):
        scm.complete_merge(handle, merge_sha="m-sha")
    assert scm.pr_state(PR) == "ready"
    h2 = scm.request_merge(PR, scm.pr_head(PR), MergeMethod.MERGE, "m2")
    scm.fail_merge(h2)  # the test control
    res = scm.poll_merge(h2)
    assert res.state is MergeState.FAILED
    assert res.reason is MergeReason.REJECTED
    assert res.receipt is not None
    assert res.receipt.simulated
    with pytest.raises(RefusedError):
        scm.complete_merge(h2, merge_sha="x")


def test_a_new_request_on_a_pr_already_merged_at_that_sha_is_success() -> None:
    scm, spy = _scm()
    head = _ready_pr(scm)
    handle = scm.request_merge(PR, head, MergeMethod.SQUASH, "m1")
    scm.complete_merge(handle, merge_sha="m-sha")
    again = scm.request_merge(PR, head, MergeMethod.SQUASH, "m-new-key")
    assert scm.poll_merge(again).state is MergeState.MERGED
    assert len(scm.merges()) == 1
    assert len(spy.applied("request_merge")) == 1  # the second succeeded but changed nothing
    assert spy.calls_for("request_merge")[1].noop
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
    scm.close_pr(PR, "c2")  # closing twice is fine, and changes nothing
    assert scm.spy.calls_for("close_pr")[-1].noop


def test_closing_a_pr_cancels_its_pending_merge() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    handle = scm.request_merge(PR, head, MergeMethod.MERGE, "m1")
    scm.close_pr(PR, "c")
    cancelled = scm.poll_merge(handle)
    assert cancelled.state is MergeState.DEQUEUED
    assert cancelled.receipt is not None
    assert cancelled.receipt.simulated


def test_a_merged_pr_cannot_be_closed() -> None:
    scm, _ = _scm()
    handle = scm.request_merge(PR, _ready_pr(scm), MergeMethod.MERGE, "m1")
    scm.complete_merge(handle, merge_sha="m")
    with pytest.raises(RefusedError):
        scm.close_pr(PR, "c")
    assert scm.pr_state(PR) == "merged"


def test_promote_fast_forwards_but_never_rewrites_a_branch() -> None:
    scm, spy = _scm()
    head = _advance(scm, "sto/x", "p1")
    scm.promote(REPO, head, "sto-approved/x", "k1")
    assert scm.head(REPO, "sto-approved/x") == head
    newer = _advance(scm, "sto/x", "p2")  # the second round (qa_fix, review, promote)
    scm.promote(REPO, newer, "sto-approved/x", "k2")
    assert scm.head(REPO, "sto-approved/x") == newer
    with pytest.raises(RefusedError):
        scm.promote(REPO, head, "sto-approved/x", "k3")  # backwards
    side = scm.create_commit(REPO, PatchRef("side"), "sha0").sha
    with pytest.raises(RefusedError):
        scm.promote(REPO, side, "sto-approved/x", "k4")  # diverged
    with pytest.raises(UnknownRefError):
        scm.promote(REPO, "no-such-sha", "sto-approved/y", "k5")
    assert scm.head(REPO, "sto-approved/x") == newer
    assert len(spy.applied("promote")) == 2
    scm.promote(REPO, newer, "sto-approved/x", "k6")  # same sha, new key: found, not a change
    assert spy.calls_for("promote")[-1].noop


def test_promote_refuses_the_base_of_an_open_pr() -> None:
    scm, spy = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    head = _advance(scm, "sto/x", "p1")
    with pytest.raises(RefusedError):
        scm.promote(REPO, head, "main", "k1")  # main would move to unmerged code
    assert scm.head(REPO, "main") == "sha0"
    assert spy.applied("promote") == ()


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
        scm.open_revert_pr(REPO, "never-merged", "k")
    head = _ready_pr(scm)
    scm.complete_merge(scm.request_merge(PR, head, MergeMethod.MERGE, "m"), merge_sha="m-sha")
    first = scm.open_revert_pr(REPO, "m-sha", "rk1")
    # a declared revert and the engine's implicit one open one PR (PLAN 6.3)
    assert scm.open_revert_pr(REPO, "m-sha", "rk2").external_id == first.external_id
    revert = PrRef.of(REPO, first)  # a real PR with a number, a branch and a head
    assert scm.pr_state(revert) == "ready"
    assert scm.pr_head(revert)
    assert revert != PR
    with pytest.raises(UnknownRefError):
        scm.open_revert_pr(RepoRef("other", "repo"), "m-sha", "rk3")
    assert scm.trigger_workflow(REPO, DispatchSpec("release.yml", "main"), "w").simulated
    assert scm.ci_trust(REPO).trusted


def test_scm_parse_event_delivers_changes() -> None:
    scm, _ = _scm()
    push = {"kind": "push", "repo": "acme/app", "branch": "main", "sha": "abc"}
    pr = {"kind": "pr", "repo": "acme/app", "pr": 3}
    check = {"kind": "check", "repo": "acme/app", "sha": "abc", "check": "sto"}
    got = scm.parse_event(_raw(changes=[push, pr, check]))
    assert [c.kind for c in got] == [ChangeKind.PUSH, ChangeKind.PR, ChangeKind.CHECK]
    assert (got[0].repo, got[0].branch, got[0].sha) == (REPO, "main", "abc")
    assert got[1].pr == PrRef(REPO, 3)
    assert got[2].check == "sto"
    assert scm.parse_event(RawWebhook({}, b"")) == []
    for bad in (b"{", b"[]", b'{"changes": [{"kind": "pr", "repo": "no-slash"}]}'):
        with pytest.raises(MalformedWebhookError):
            scm.parse_event(RawWebhook({}, bad))


def test_every_write_path_returns_a_simulated_receipt() -> None:
    scm, _ = _scm()
    scm.seed_branch(REPO, "sto/y", "sha2", parent="sha0")
    t, _ = _tickets()
    n = FakeNotifier()
    scm.ensure_draft_pr(SPEC, "k")
    _advance(scm, "main", "base1")
    updated = scm.merge_base_into(PR, "sha1", "u1")
    ready = scm.mark_ready(PR, "r")
    handle = scm.request_merge(PR, updated.sha, MergeMethod.MERGE, "m1")
    scm.complete_merge(handle, merge_sha="m-sha")
    sent = n.send(GateMessage("g", "s", "d"), "n1")
    base = scm.head(REPO, "main")
    receipts: list[Receipt | None] = [
        t.comment(TREF, "x", "t1"),
        t.transition(TREF, StatusIntent.DONE, "t2"),
        sent,
        n.update(sent, GateMessage("g", "s2", "d")),
        ready,
        scm.ensure_draft_pr(PrSpec(REPO, "sto/y", "main", "t", "b"), "s1"),
        scm.close_pr(PrRef(REPO, 2), "s3"),
        scm.move_ref(REPO, "main", scm.create_commit(REPO, PatchRef("z"), base), base),
        scm.promote(REPO, updated.sha, "sto-approved/x", "s4"),
        scm.open_revert_pr(REPO, "m-sha", "s5"),
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


def test_idempotency_is_keyed_by_method_and_key() -> None:
    scm, _ = _scm()
    scm.ensure_draft_pr(SPEC, "k")
    scm.mark_ready(PR, "K")
    scm.close_pr(PR, "K")  # same key, other method: not a replay
    assert scm.pr_state(PR) == "closed"


def test_a_merge_lands_on_the_base_and_its_commit_is_real() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    handle = scm.request_merge(PR, head, MergeMethod.SQUASH, "m1")
    scm.complete_merge(handle, merge_sha="m-sha")
    assert scm.head(REPO, "main") == "m-sha"
    assert scm.snapshot(REPO, "m-sha").uri
    scm.publish_check(CheckSpec(REPO, "m-sha", "post-merge", "success"), "c")
    follow = scm.create_commit(REPO, PatchRef("after"), "m-sha")
    assert follow.parent == "m-sha"


def test_a_head_behind_a_moved_base_is_stale_until_the_base_is_merged_in() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    _advance(scm, "main", "trunk-moved")
    with pytest.raises(StaleHeadError):
        scm.request_merge(PR, head, MergeMethod.SQUASH, "m1")
    updated = scm.merge_base_into(PR, head, "upd")
    handle = scm.request_merge(PR, updated.sha, MergeMethod.SQUASH, "m2")
    assert scm.poll_merge(handle).state is MergeState.PENDING
    scm.require_up_to_date = False  # waived by OrgPolicy (PLAN 6.4)
    other = _advance(scm, "main", "trunk-moved-again")
    assert other
    assert scm.poll_merge(handle).state is MergeState.PENDING


def test_a_base_that_moves_under_a_pending_merge_fails_it_as_stale() -> None:
    scm, _ = _scm()
    handle = scm.request_merge(PR, _ready_pr(scm), MergeMethod.SQUASH, "m1")
    _advance(scm, "main", "trunk-moved")
    res = scm.poll_merge(handle)
    assert (res.state, res.reason) == (MergeState.FAILED, MergeReason.STALE)
    assert res.receipt is not None


def test_a_merge_conflict_fails_the_merge_with_a_reason() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    scm.set_merge_conflict(PR, True)
    handle = scm.request_merge(PR, head, MergeMethod.MERGE, "m1")
    res = scm.poll_merge(handle)
    assert (res.state, res.reason) == (MergeState.FAILED, MergeReason.CONFLICT)
    assert scm.merge_method(handle) is MergeMethod.MERGE


def test_a_pending_merge_hands_back_the_same_handle() -> None:
    scm, spy = _scm()
    head = _ready_pr(scm)
    first = scm.request_merge(PR, head, MergeMethod.MERGE, "m1")
    assert scm.request_merge(PR, head, MergeMethod.MERGE, "m2") == first
    assert len(scm.merges()) == 1
    assert spy.calls_for("request_merge")[-1].noop


def test_a_draft_pr_needs_commits_and_a_branch_other_than_its_base() -> None:
    scm, spy = _scm()
    scm.seed_branch(REPO, "same", "sha0")
    with pytest.raises(RefusedError):
        scm.ensure_draft_pr(PrSpec(REPO, "same", "main", "t", "b"), "k1")  # nothing ahead
    with pytest.raises(RefusedError):
        scm.ensure_draft_pr(PrSpec(REPO, "main", "main", "t", "b"), "k2")  # base is head
    assert spy.applied() == ()


def test_pr_receipts_route_back_to_a_pr_ref() -> None:
    scm, _ = _scm()
    receipt = scm.ensure_draft_pr(SPEC, "k")
    assert PrRef.of(REPO, receipt) == PR
    with pytest.raises(RefusedError):
        PrRef.of(REPO, Receipt("not-a-number", "", True))


def test_spy_noop_marks_calls_that_changed_nothing() -> None:
    t, spy = _tickets()
    scm, sspy = _scm()
    scm.ensure_draft_pr(SPEC, "k1")
    scm.ensure_draft_pr(SPEC, "k2")  # found
    scm.mark_ready(PR, "r1")
    scm.mark_ready(PR, "r2")  # already ready
    assert [c.noop for c in sspy.calls_for("ensure_draft_pr")] == [False, True]
    assert [c.noop for c in sspy.calls_for("mark_ready")] == [False, True]
    assert len(sspy.applied()) == 2
    t.transition(TREF, StatusIntent.DONE, "t1")
    t.transition(TREF, StatusIntent.DONE, "t2")  # already there is success (PLAN 6.3)
    assert len(spy.applied("transition")) == 1


def test_a_write_not_read_back_is_not_applied() -> None:
    t, spy = _tickets()
    t.read_back_verified = False
    assert not t.comment(TREF, "x", "k").read_back_verified
    assert t.comments(TREF) == []
    assert spy.applied() == ()
    scm, _ = _scm()
    scm.read_back_verified = False
    scm.ensure_draft_pr(SPEC, "k")
    with pytest.raises(UnknownRefError):
        scm.pr_state(PR)
    n = FakeNotifier()
    n.read_back_verified = False
    n.send(GateMessage("g", "s", "d"), "k")
    assert n.messages() == []


def test_a_non_sto_error_still_reaches_the_spy(monkeypatch: pytest.MonkeyPatch) -> None:
    scm, spy = _scm()

    def boom(*a: object) -> None:
        raise RuntimeError("bug in the fake")

    monkeypatch.setattr(scm, "_known_commit", boom)
    with pytest.raises(RuntimeError):
        scm.create_commit(REPO, PatchRef("p"), "sha0")
    assert spy.calls_for("create_commit")[0].error == "RuntimeError"


def test_transition_changes_status_and_search_filters_apply() -> None:
    t, _ = _tickets()
    t.add_ticket(
        Ticket(
            TicketRef("fake", "T-2"),
            "two",
            "",
            "open",
            ("bug", "sto"),
            project="P",
            issue_type="Bug",
        )
    )
    t.transition(TREF, StatusIntent.IN_REVIEW, "k")
    assert t.get(TREF).status == "in_review"

    def keys(q: IntakeQuery) -> list[str]:
        return [i.ref.key for i in t.search(q, None).items]

    assert keys(IntakeQuery(status="in_review")) == ["T-1"]
    assert keys(IntakeQuery(labels=("sto",))) == ["T-2"]
    assert keys(IntakeQuery(labels=("sto", "nope"))) == []
    assert keys(IntakeQuery(project="P")) == ["T-2"]
    assert keys(IntakeQuery(issue_types=("Bug", "Task"))) == ["T-2"]
    assert keys(IntakeQuery(issue_types=("Epic",))) == []
    assert sorted(keys(IntakeQuery())) == ["T-1", "T-2"]


def test_revision_covers_body_route_names_and_is_unshiftable() -> None:
    def rev(
        title: str = "t", body: str = "b", ac: str = "", routes: tuple[tuple[str, str], ...] = ()
    ) -> str:
        return Ticket(
            TREF, title, body, "open", acceptance_criteria=ac, route_fields=routes
        ).revision

    assert rev(body="b") != rev(body="b2")
    assert rev(routes=(("a", "1"),)) != rev(routes=(("b", "1"),))
    assert rev(routes=(("a", "1"), ("b", "2"))) == rev(routes=(("b", "2"), ("a", "1")))
    assert rev(routes=((" a ", "1"),)) == rev(routes=(("a", "1"),))
    # text cannot move between fields through a separator character
    assert rev(title="a\0b", body="c") != rev(title="a", body="b\0c")
    assert rev(routes=(("a=b", "c"),)) != rev(routes=(("a", "b=c"),))


def test_ci_trust_can_report_untrusted() -> None:
    scm, _ = _scm()
    scm.trusted = False
    report = scm.ci_trust(REPO)
    assert not report.trusted
    assert report.reasons


def test_a_gate_message_stays_in_its_channel_and_an_edit_records_its_editor() -> None:
    n = FakeNotifier()
    a = n.send(GateMessage("g1", "s", "d", channel="C1"), "k1")
    n.send(GateMessage("g2", "s", "d", channel="C2"), "k2")
    assert [m.gate_id for m in n.messages(channel="C1")] == ["g1"]
    n.update(a, GateMessage("g1", "closed", "d", channel="C1"))
    with pytest.raises(RefusedError):
        n.update(a, GateMessage("g1", "closed", "d", channel="C2"))  # a message cannot move
    assert [m.summary for m in n.messages(channel="C1")] == ["closed"]
    t, _ = _tickets()
    before = t.get(TREF).revision
    t.edit(TREF, editor="u2")
    assert t.get(TREF).editor == "u2"
    assert t.get(TREF).revision == before  # who edited is not part of the revision
    t.edit(TREF, editor="u3", title="changed")
    assert (t.get(TREF).editor, t.get(TREF).title) == ("u3", "changed")
    assert t.get(TREF).revision != before


def test_installation_events_are_scm_only_and_each_kind_needs_its_target() -> None:
    scm, _ = _scm()
    t, _ = _tickets()
    got = scm.parse_event(_raw(changes=[{"kind": "installation", "repo": "acme/app"}]))
    assert [c.kind for c in got] == [ChangeKind.INSTALLATION]
    bad_for_scm = [
        {"kind": "pr"},
        {"kind": "pr", "repo": "acme/app"},
        {"kind": "push", "repo": "acme/app", "branch": "main"},
        {"kind": "check", "repo": "acme/app", "sha": "x"},
        {"kind": "review", "repo": "acme/app"},
        {"kind": "merge_group", "repo": "acme/app"},
        {"kind": "installation"},
        {"kind": "ticket", "ticket": "T-1"},  # a ticket event does not belong on the SCM port
        {"kind": "pr", "repo": "acme/app", "pr": True},
        {"kind": "pr", "repo": "acme/app", "pr": 0},
        {"kind": "push", "repo": "acme/app", "branch": None, "sha": "x"},
    ]
    for item in bad_for_scm:
        with pytest.raises(MalformedWebhookError):
            scm.parse_event(_raw(changes=[item]))
    for item in (
        {"kind": "ticket"},
        {"kind": "ticket", "ticket": ""},
        {"kind": "pr", "repo": "a/b", "pr": 1},
    ):
        with pytest.raises(MalformedWebhookError):
            t.parse_event(_raw(changes=[item]))


def test_a_veto_needs_no_digest_but_an_approval_does_and_fields_must_be_strings() -> None:
    n = FakeNotifier()
    veto = n.parse_action(_raw(gate_id="g1", kind="reject", actor="u1", comment="no"))
    assert veto is not None
    assert veto.subject_digest is None
    nulled = n.parse_action(
        _raw(gate_id="g1", kind="request_changes", actor="u1", subject_digest=None, comment="fix")
    )
    assert nulled is not None
    assert nulled.subject_digest is None
    bad: list[dict[str, object]] = [
        {"gate_id": "g1", "kind": "approve", "actor": "u1"},
        {"gate_id": "g1", "kind": "approve", "actor": "u1", "subject_digest": ""},
        {"gate_id": "g1", "kind": "approve", "actor": "u1", "subject_digest": "  "},
        {"gate_id": "g1", "kind": "reject", "actor": "u1"},  # a reject needs its reason
        {"gate_id": "g1", "kind": "reject", "actor": "u1", "comment": "  "},
        {"gate_id": "g1", "kind": "request_changes", "actor": "u1", "comment": ""},
        {"gate_id": "g1", "kind": "approve", "actor": "u1", "subject_digest": None},
        {"gate_id": None, "kind": "reject", "actor": "u1"},
        {"gate_id": "g1", "kind": "reject", "actor": None},
        {"gate_id": "g1", "kind": "reject", "actor": 7},
        {"gate_id": "g1", "kind": "reject", "actor": "u1", "subject_digest": 5},
        {"gate_id": "", "kind": "reject", "actor": "u1"},
    ]
    for body in bad:
        with pytest.raises(MalformedWebhookError):
            n.parse_action(_raw(**body))


def test_a_retry_after_an_unverified_write_applies_it_under_the_same_key() -> None:
    t, spy = _tickets()
    t.read_back_verified = False
    assert not t.comment(TREF, "x", "K").read_back_verified
    assert t.comments(TREF) == []
    t.read_back_verified = True
    retry = t.comment(TREF, "x", "K")  # PLAN 6.3: retries keep their key
    assert retry.read_back_verified
    assert t.comments(TREF) == ["x"]
    assert [(c.replayed, c.noop) for c in spy.calls_for("comment")] == [
        (False, True),
        (False, False),
    ]
    assert t.comment(TREF, "x", "K") == retry  # now it is a replay
    assert t.comments(TREF) == ["x"]


def test_unapplied_writes_still_get_distinct_ids() -> None:
    n = FakeNotifier()
    n.read_back_verified = False
    a = n.send(GateMessage("g1", "s", "d"), "k1")
    b = n.send(GateMessage("g2", "s", "d"), "k2")
    assert a.external_id != b.external_id


def test_an_unapplied_merge_request_polls_as_not_merged() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    scm.read_back_verified = False
    handle = scm.request_merge(PR, head, MergeMethod.MERGE, "m1")
    assert scm.poll_merge(handle).state is MergeState.PENDING  # not merged, and no error
    assert scm.merges() == []
    with pytest.raises(RefusedError):
        scm.dequeue(PR, head)  # nothing is queued
    assert scm.pr_state(PR) == "ready"


@pytest.mark.parametrize("bad", ["-3", "0", " 12 ", "1_000", "١٢", "012", "revert-3", "+4"])
def test_a_pr_receipt_is_only_ascii_digits_above_zero(bad: str) -> None:
    with pytest.raises(RefusedError):
        PrRef.of(REPO, Receipt(bad, "", True))
    assert PrRef.of(REPO, Receipt("12", "", True)) == PrRef(REPO, 12)


def test_the_fake_does_not_claim_a_merge_queue_it_does_not_model() -> None:
    assert not FakeScm().capabilities.merge_queue


def test_an_injected_transient_failure_applies_nothing_and_a_retry_succeeds() -> None:
    t, spy = _tickets()
    t.fail_next("comment")
    with pytest.raises(TransientError):
        t.comment(TREF, "x", "K")
    assert t.comments(TREF) == []
    assert spy.calls_for("comment")[0].error == "TransientError"
    t.comment(TREF, "x", "K")  # the retry, same key
    assert t.comments(TREF) == ["x"]
    t.comment(TREF, "y", "K2")  # only one failure was injected


def test_a_lost_response_applies_the_write_and_a_retry_replays_it() -> None:
    scm, spy = _scm()
    scm.lose_response_next("ensure_draft_pr")
    with pytest.raises(TransientError):
        scm.ensure_draft_pr(SPEC, "K")
    assert scm.pr_state(PR) == "draft"  # it did happen
    assert spy.calls_for("ensure_draft_pr")[0].error == "TransientError"
    again = scm.ensure_draft_pr(SPEC, "K")
    assert PrRef.of(REPO, again) == PR
    assert len(scm._prs) == 1  # noqa: SLF001


def test_a_release_dispatch_goes_stale_when_the_ref_moved() -> None:
    scm, spy = _scm()
    tested = scm.head(REPO, "main")
    scm.trigger_workflow(REPO, DispatchSpec("release.yml", "main", expected_head=tested), "w1")
    _advance(scm, "main", "moved")
    with pytest.raises(StaleHeadError):
        scm.trigger_workflow(REPO, DispatchSpec("release.yml", "main", expected_head=tested), "w2")
    assert len(spy.applied("trigger_workflow")) == 1


def test_a_squash_or_rebase_merge_does_not_make_the_head_an_ancestor() -> None:
    for method, parents_include_head in (
        (MergeMethod.MERGE, True),
        (MergeMethod.SQUASH, False),
        (MergeMethod.REBASE, False),
    ):
        scm, _ = _scm()
        head = _ready_pr(scm)
        base = scm.head(REPO, "main")
        handle = scm.request_merge(PR, head, method, "m")
        scm.complete_merge(handle, merge_sha="m-sha")
        expected = (base, head) if parents_include_head else (base,)
        assert scm.parents(REPO, "m-sha") == expected
        if parents_include_head:
            with pytest.raises(RefusedError):
                scm.ensure_draft_pr(SPEC, "again")  # nothing is ahead of the base
        else:
            # the squash commit does not contain the branch's commits, so it can be reopened
            assert PrRef.of(REPO, scm.ensure_draft_pr(SPEC, "again")).number == 2


def test_seed_branch_refuses_an_unrelated_root_and_an_unknown_parent() -> None:
    scm, _ = _scm()
    with pytest.raises(RefusedError):
        scm.seed_branch(REPO, "orphan", "zzz")  # would read as "the base moved"
    with pytest.raises(UnknownRefError):
        scm.seed_branch(REPO, "orphan", "zzz", parent="nope")
    scm.seed_branch(REPO, "alias", "sha0")  # an existing commit is fine
    scm.seed_branch(RepoRef("other", "repo"), "main", "r0")  # the first commit of a repo is a root


def test_complete_merge_refuses_a_duplicate_merge_sha() -> None:
    scm, _ = _scm()
    handle = scm.request_merge(PR, _ready_pr(scm), MergeMethod.MERGE, "m")
    with pytest.raises(RefusedError):
        scm.complete_merge(handle, merge_sha="sha1")
    assert scm.poll_merge(handle).state is MergeState.PENDING


def test_the_up_to_date_waiver_lets_a_request_through_a_moved_base() -> None:
    scm, _ = _scm()
    head = _ready_pr(scm)
    _advance(scm, "main", "trunk-moved")
    scm.require_up_to_date = False
    handle = scm.request_merge(PR, head, MergeMethod.MERGE, "m")
    assert scm.poll_merge(handle).state is MergeState.PENDING
