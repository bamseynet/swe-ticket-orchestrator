"""Intake (D2-17): closed selectors, sprint filter, WIP, windows, and T11 edits.

Persistence runs on every store (memory, SQLite, DynamoDB on moto) through the D3-10 fixtures.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from store_contract import A, B
from test_dynamodb import Env, env  # noqa: F401  (env is a fixture)

from sto.config.schema import Intake, TeamConfig, load_document
from sto.domain.states import RunStatus
from sto.engine import intake as I
from sto.gates.subject import TicketFields, ticket_revision
from sto.store import queries
from sto.store.memory import MemoryStore
from sto.store.ports import IndexedStore, Key, Put
from sto.store.sqlite import SqliteStore

UTC = dt.UTC
NOW = dt.datetime(2026, 11, 4, 10, 0, tzinfo=UTC)  # a Wednesday
ALICE = "https://idp|alice"
MALLORY = "https://idp|mallory"


def sel(**kw: Any) -> Intake:
    base: dict[str, Any] = {"source": "jira", "project": "PAY", "label": "agent-ready"}
    return Intake.model_validate(base | kw)


def team_cfg(extra: str = "") -> TeamConfig:
    doc = (
        "apiVersion: sto/v1\nkind: TeamConfig\nmetadata: {team: team-a}\n"
        "budgets: {run_usd: 5, team_monthly_usd: 100}\n" + extra
    )
    cfg = load_document(doc)
    assert isinstance(cfg, TeamConfig)
    return cfg


def fields(summary: str = "s", **routes: str) -> TicketFields:
    return TicketFields(summary, "d", ("ac",), routes)


def ticket(**kw: Any) -> I.IntakeTicket:
    base: dict[str, Any] = {
        "source": "jira",
        "ref": "PAY-1",
        "project": "PAY",
        "labels": ("agent-ready",),
        "issue_type": "Story",
        "in_active_sprint": True,
        "repo_public": False,
        "extra_filter_matched": True,
        "fields": fields(risk="High"),
        "actor": ALICE,
    }
    return I.IntakeTicket(**(base | kw))


# --- closed selectors and V12 ------------------------------------------------------------------


class TestOverlap:
    def test_same_project_and_label_overlap(self) -> None:
        assert I.selectors_overlap(sel(), sel())

    @pytest.mark.parametrize(
        "other",
        [
            {"label": "other"},
            {"project": "OPS"},
            {"source": "github"},
            {"issue_types": ["Bug"], "label": "other"},
        ],
    )
    def test_a_different_source_project_or_label_does_not(self, other: dict[str, Any]) -> None:
        assert not I.selectors_overlap(sel(), sel(**other))

    def test_issue_types_disjoint_do_not_overlap_but_none_means_all(self) -> None:
        assert not I.selectors_overlap(sel(issue_types=["Bug"]), sel(issue_types=["Story"]))
        assert I.selectors_overlap(sel(issue_types=["Bug", "Story"]), sel(issue_types=["Story"]))
        assert I.selectors_overlap(sel(), sel(issue_types=["Story"]))
        assert I.selectors_overlap(sel(issue_types=["Story"]), sel())

    def test_case_and_unicode_form_cannot_dodge_the_check(self) -> None:
        assert I.selectors_overlap(sel(label="Agent-Ready"), sel(label="agent-ready"))
        assert I.selectors_overlap(sel(project="café"), sel(project="café"))

    def test_extra_filter_never_separates_two_selectors(self) -> None:
        assert I.selectors_overlap(sel(extra_filter="a = 1"), sel(extra_filter="a = 2"))

    def test_publish_refuses_an_overlap_and_names_the_other_workflow(self) -> None:
        with pytest.raises(I.OverlappingIntakeError, match="team-b/other") as err:
            I.check_publish(("team-a", "new"), sel(), {("team-b", "other"): sel()})
        assert err.value.workflows == (("team-b", "other"),)

    def test_publish_accepts_disjoint_selectors_and_ignores_its_own_old_version(self) -> None:
        published = {("team-a", "x"): sel(label="other"), ("team-a", "me"): sel()}
        I.check_publish(("team-a", "me"), sel(), published)  # no error

    def test_find_overlaps_lists_each_pair_once(self) -> None:
        pairs = I.find_overlaps({("t", "a"): sel(), ("t", "b"): sel(), ("t", "c"): sel(label="z")})
        assert pairs == [(("t", "a"), ("t", "b"))]


class TestMatching:
    def test_a_ticket_matches_its_selector(self) -> None:
        assert I.matches(sel(), ticket())

    @pytest.mark.parametrize(
        "change",
        [
            {"source": "github"},
            {"project": "OPS"},
            {"labels": ("other",)},
            {"labels": ()},
        ],
    )
    def test_source_project_and_label_must_all_match(self, change: dict[str, Any]) -> None:
        assert not I.matches(sel(), ticket(**change))

    def test_issue_types_narrow(self) -> None:
        assert I.matches(sel(issue_types=["Story"]), ticket())
        assert not I.matches(sel(issue_types=["Bug"]), ticket())

    def test_extra_filter_can_only_narrow(self) -> None:
        s = sel(extra_filter='"Risk" is not EMPTY')
        assert I.matches(s, ticket())
        assert not I.matches(s, ticket(extra_filter_matched=False))
        assert I.matches(sel(), ticket(extra_filter_matched=False))  # no filter declared


# --- decisions without a store -----------------------------------------------------------------


class TestDecide:
    def decide(self, **kw: Any) -> I.Decision:
        args: dict[str, Any] = {
            "workflows": {"w": sel()},
            "ticket": ticket(),
            "public_repo_intake": False,
        }
        return I.decide(**(args | kw))

    def test_a_matching_ticket_starts(self) -> None:
        d = self.decide()
        assert (d.start, d.workflow, d.reason) == (True, "w", None)

    def test_no_match_starts_nothing(self) -> None:
        d = self.decide(ticket=ticket(labels=()))
        assert (d.start, d.reason) == (False, "no_match")

    def test_a_ticket_matching_two_workflows_starts_nothing(self) -> None:
        d = self.decide(workflows={"w": sel(), "v": sel(issue_types=["Story"])})
        assert (d.start, d.reason) == (False, "ambiguous")
        assert d.workflows == ("v", "w")

    def test_active_only_skips_a_ticket_outside_the_sprint(self) -> None:
        wf = {"w": sel(sprint={"mode": "active_only"})}
        d = self.decide(workflows=wf, ticket=ticket(in_active_sprint=False))
        assert (d.start, d.reason) == (False, "outside_active_sprint")
        assert self.decide(workflows=wf).start

    def test_an_unknown_sprint_membership_is_outside_the_sprint(self) -> None:
        wf = {"w": sel(sprint={"mode": "active_only"})}
        assert not self.decide(workflows=wf, ticket=ticket(in_active_sprint=None)).start

    def test_mode_any_ignores_the_sprint(self) -> None:
        wf = {"w": sel(sprint={"mode": "any"})}
        assert self.decide(workflows=wf, ticket=ticket(in_active_sprint=False)).start

    def test_a_public_repo_needs_the_opt_in(self) -> None:
        d = self.decide(ticket=ticket(repo_public=True))
        assert (d.start, d.reason) == (False, "public_repo_not_opted_in")
        assert self.decide(ticket=ticket(repo_public=True), public_repo_intake=True).start

    def test_an_unknown_repo_visibility_is_public(self) -> None:
        assert not self.decide(ticket=ticket(repo_public=None)).start

    def test_an_unknown_actor_cannot_start_a_run(self) -> None:
        for actor in (None, "", "alice", "|alice", "idp|", " idp|alice"):
            d = self.decide(ticket=ticket(actor=actor))
            assert (d.start, d.reason) == (False, "unknown_actor"), actor


# --- the record --------------------------------------------------------------------------------


class TestRecord:
    def test_records_actor_revision_and_frozen_route_inputs(self) -> None:
        t = ticket(
            fields=fields(
                " risk ",
            )
        )
        rec = I.record(t, "w", NOW)
        assert rec.actor == ALICE
        assert rec.ticket_revision == ticket_revision(t.fields)
        assert rec.route_inputs == dict(t.fields.route_inputs)
        assert rec.started_at == NOW.isoformat()

    def test_route_inputs_are_normalised_by_the_subject_code(self) -> None:
        t = ticket(fields=TicketFields("s", "d", (), {"risk ": " High "}))
        assert I.record(t, "w", NOW).route_inputs == {"risk": "High"}

    def test_two_keys_that_collide_after_normalising_are_refused(self) -> None:
        with pytest.raises(ValueError, match="two keys"):
            TicketFields("s", "d", (), {"risk": "a", "risk ": "b"})

    def test_a_naive_clock_is_refused(self) -> None:
        with pytest.raises(ValueError, match="timezone"):
            I.record(ticket(), "w", NOW.replace(tzinfo=None))

    def test_the_wire_form_round_trips(self) -> None:
        rec = I.record(ticket(), "w", NOW)
        assert I.IntakeRecord.from_data(rec.to_data()) == rec

    def test_a_malformed_stored_record_is_refused(self) -> None:
        data = I.record(ticket(), "w", NOW).to_data()
        del data["actor"]
        with pytest.raises(ValueError, match="actor"):
            I.IntakeRecord.from_data(data)


# --- start, duplicates and WIP, on every store -------------------------------------------------


class StoreContract:
    def open(
        self,
        store: IndexedStore,
        n: int,
        *,
        scope: Any = A,
        ref: str = "PAY-1",
        wip_limit: int | None = None,
        now: dt.datetime = NOW,
        wf: dict[str, Intake] | None = None,
        **kw: Any,
    ) -> I.IntakeOutcome:
        return I.open_run(
            store,
            scope,
            workflows=wf or {"w": sel()},
            ticket=ticket(ref=ref, **kw),
            public_repo_intake=False,
            wip_limit=wip_limit,
            run_id=f"r{n}",
            now=now,
        )

    def test_a_started_run_is_queued_admitted_and_carries_its_record(
        self, store: IndexedStore
    ) -> None:
        out = self.open(store, 1)
        assert (out.status, out.admitted, out.reason) == ("started", True, None)
        item = store.get(A, Key("RUN#r1", "META"))
        assert item is not None
        assert item.data["status"] == "QUEUED"
        rec = I.IntakeRecord.from_data(item.data["intake"])
        assert (rec.actor, rec.workflow) == (ALICE, "w")
        assert item.data["workflow"] == "w"

    def test_a_duplicate_active_run_starts_nothing(self, store: IndexedStore) -> None:
        self.open(store, 1)
        out = self.open(store, 2)
        assert (out.status, out.reason, out.run_id) == ("skipped", "duplicate_active", "r1")
        assert store.get(A, Key("RUN#r2", "META")) is None

    def test_another_ticket_or_team_is_not_a_duplicate(self, store: IndexedStore) -> None:
        self.open(store, 1)
        assert self.open(store, 2, ref="PAY-2").status == "started"
        assert self.open(store, 3, scope=B).status == "started"

    def test_a_finished_holder_is_taken_over(self, store: IndexedStore) -> None:
        self.open(store, 1)
        key = Key("RUN#r1", "META")
        store.transact(A, [Put(key, {"status": "DONE"})])  # ended without releasing
        assert self.open(store, 2).status == "started"

    def test_skipped_tickets_write_nothing(self, store: IndexedStore) -> None:
        for n, kw in enumerate(
            [{"labels": ()}, {"repo_public": True}, {"actor": None}, {"in_active_sprint": False}]
        ):
            wf = {"w": sel(sprint={"mode": "active_only"})}
            out = self.open(store, n, wf=wf, **kw)  # type: ignore[arg-type]
            assert out.status == "skipped"
            assert store.get(A, Key(f"RUN#r{n}", "META")) is None
        assert queries.runs_for_ticket(store, A, "jira", "PAY-1").items == ()

    def test_an_ambiguous_ticket_starts_nothing_and_says_which_workflows(
        self, store: IndexedStore
    ) -> None:
        out = self.open(store, 1, wf={"a": sel(), "b": sel()})
        assert (out.status, out.reason, out.workflows) == ("skipped", "ambiguous", ("a", "b"))
        assert store.get(A, Key("RUN#r1", "META")) is None

    def test_wip_holds_runs_queued(self, store: IndexedStore) -> None:
        a = self.open(store, 1, ref="1", wip_limit=1)
        assert a.admitted
        self.set_status(store, 1, "RUNNING")
        b = self.open(store, 2, ref="2", wip_limit=1)
        assert (b.status, b.admitted, b.reason) == ("queued", False, "wip_limit")
        item = store.get(A, Key("RUN#r2", "META"))
        assert item is not None
        assert item.data["status"] == "QUEUED"
        # the held run still owns its ticket
        assert self.open(store, 3, ref="2", wip_limit=1).reason == "duplicate_active"

    def set_status(self, store: IndexedStore, n: int, status: str) -> None:
        key = Key(f"RUN#r{n}", "META")
        item = store.get(A, key)
        assert item is not None
        data = dict(item.data) | {"status": status}
        store.transact(
            A,
            [
                Put(
                    key,
                    data,
                    attrs=queries.run_attrs(
                        RunStatus(status), NOW.isoformat(), key, ticket=("jira", f"{n}")
                    ),
                )
            ],
        )

    def test_wip_counts_running_waiting_and_blocked_but_not_queued_or_ended(
        self, store: IndexedStore
    ) -> None:
        for n, s in enumerate(
            ["RUNNING", "WAITING_HUMAN", "WAITING_EXTERNAL", "BLOCKED", "QUEUED", "DONE"], 1
        ):
            self.open(store, n, ref=str(n))
            self.set_status(store, n, s)
        assert I.active_count(store, A) == 4
        assert I.active_count(store, B) == 0

    def test_wip_count_walks_every_page(self, store: IndexedStore) -> None:
        for n in range(1, 8):
            self.open(store, n, ref=str(n))
            self.set_status(store, n, "RUNNING")
        assert I.active_count(store, A, page_size=2) == 7

    def test_a_free_slot_admits_the_oldest_queued_runs_first(self, store: IndexedStore) -> None:
        for n in (1, 2, 3):
            self.open(store, n, ref=str(n), wip_limit=1, now=NOW - dt.timedelta(minutes=n))
        # r3 is the oldest, so the order is by time and not by id
        assert I.admit_queued(store, A, wip_limit=1, page_size=1) == ["r3"]
        assert I.admit_queued(store, A, wip_limit=2, page_size=1) == ["r3", "r2"]
        assert I.admit_queued(store, A, wip_limit=None, page_size=1) == ["r3", "r2", "r1"]

    def test_no_slot_admits_nothing(self, store: IndexedStore) -> None:
        self.open(store, 1, ref="1")
        self.set_status(store, 1, "RUNNING")
        self.open(store, 2, ref="2")
        assert I.admit_queued(store, A, wip_limit=1) == []


class TestMemory(StoreContract):
    @pytest.fixture
    def store(self) -> IndexedStore:
        return MemoryStore()


class TestSqlite(StoreContract):
    @pytest.fixture
    def store(self, tmp_path: Path) -> Iterator[IndexedStore]:
        s = SqliteStore(tmp_path / "s.db")
        yield s
        s.close()


class TestDynamoOnMoto(StoreContract):
    @pytest.fixture
    def store(self, env: Env) -> IndexedStore:  # noqa: F811
        return env.store


# --- freeze and change windows -----------------------------------------------------------------


class TestMergeWindow:
    def test_no_windows_leaves_merge_open(self) -> None:
        w = I.merge_window(team_cfg(), NOW)
        assert (w.open, w.status, w.reason, w.until) == (True, RunStatus.RUNNING, None, None)

    def test_a_deny_window_holds_merge_in_waiting_external_until_it_ends(self) -> None:
        cfg = team_cfg(
            "change_windows:\n  deny:\n"
            "    - {from: '2026-11-04T09:00:00Z', to: '2026-11-04T12:00:00Z', reason: audit}\n"
        )
        w = I.merge_window(cfg, NOW)
        assert (w.open, w.status) == (False, RunStatus.WAITING_EXTERNAL)
        assert "audit" in (w.reason or "")
        assert w.until == dt.datetime(2026, 11, 4, 12, tzinfo=UTC)
        assert I.merge_window(cfg, dt.datetime(2026, 11, 4, 12, tzinfo=UTC)).open  # `to` is open
        assert not I.merge_window(cfg, dt.datetime(2026, 11, 4, 9, tzinfo=UTC)).open

    def test_the_held_status_is_a_legal_move_for_a_running_run(self) -> None:
        from sto.domain import Run, RunId

        w = I.merge_window(
            team_cfg(
                "change_windows:\n  deny:\n"
                "    - {from: '2026-11-04T09:00:00Z', to: '2026-11-04T12:00:00Z', reason: x}\n"
            ),
            NOW,
        )
        run = Run(RunId(1), "team-a", status=RunStatus.RUNNING)
        assert run.advance(w.status).status is RunStatus.WAITING_EXTERNAL

    def test_allow_only_holds_outside_the_cron_and_names_when_it_reopens(self) -> None:
        cfg = team_cfg("change_windows:\n  allow_only: '* 9-16 * * 1-5'\n")
        assert I.merge_window(cfg, NOW).open
        late = dt.datetime(2026, 11, 4, 17, 30, tzinfo=UTC)
        w = I.merge_window(cfg, late)
        assert (w.open, w.until) == (False, dt.datetime(2026, 11, 5, 9, 0, tzinfo=UTC))
        sat = dt.datetime(2026, 11, 7, 10, tzinfo=UTC)
        assert I.merge_window(cfg, sat).until == dt.datetime(2026, 11, 9, 9, tzinfo=UTC)

    def test_allow_only_reads_the_team_time_zone(self) -> None:
        cfg = team_cfg(
            "calendar: {timezone: Australia/Sydney, workdays: [mon,tue,wed,thu,fri],"
            " hours: '09:00-17:00'}\nchange_windows:\n  allow_only: '* 9-16 * * 1-5'\n"
        )
        # 10:00 UTC is 21:00 in Sydney in November: closed
        assert not I.merge_window(cfg, NOW).open
        assert I.merge_window(cfg, dt.datetime(2026, 11, 4, 0, 0, tzinfo=UTC)).open  # 11:00

    def test_a_bad_cron_fails_closed(self) -> None:
        for bad in ("* * *", "61 * * * *", "* 25 * * *", "a b c d e", "*/0 * * * *"):
            w = I.merge_window(team_cfg(f"change_windows:\n  allow_only: '{bad}'\n"), NOW)
            assert not w.open, bad
            assert "allow_only" in (w.reason or ""), bad

    def test_a_sprint_freeze_holds_before_the_sprint_ends(self) -> None:
        cfg = team_cfg("sprint: {cadence: 2w, anchor: 2026-11-02, merge_freeze_before_end: 1d}\n")
        # sprint 1 is 2026-11-02 .. 2026-11-16; the freeze starts 2026-11-15 00:00 UTC
        assert I.merge_window(cfg, dt.datetime(2026, 11, 14, 23, 59, tzinfo=UTC)).open
        w = I.merge_window(cfg, dt.datetime(2026, 11, 15, 0, 0, tzinfo=UTC))
        assert (w.open, w.status) == (False, RunStatus.WAITING_EXTERNAL)
        assert w.until == dt.datetime(2026, 11, 16, tzinfo=UTC)
        # the next sprint opens the gate again
        assert I.merge_window(cfg, dt.datetime(2026, 11, 16, 0, 0, tzinfo=UTC)).open
        # and the second sprint freezes on its own last day
        assert not I.merge_window(cfg, dt.datetime(2026, 11, 29, 12, tzinfo=UTC)).open

    def test_before_the_anchor_there_is_no_sprint_to_freeze(self) -> None:
        cfg = team_cfg("sprint: {cadence: 1w, anchor: 2027-01-04, merge_freeze_before_end: 1d}\n")
        assert I.merge_window(cfg, NOW).open

    def test_the_hours_before_the_anchor_are_not_in_a_frozen_sprint(self) -> None:
        cfg = team_cfg("sprint: {cadence: 1w, anchor: 2026-11-05, merge_freeze_before_end: 1d}\n")
        assert I.merge_window(cfg, dt.datetime(2026, 11, 4, 12, tzinfo=UTC)).open

    def cron_at(self, cron: str, at: dt.datetime) -> I.MergeWindow:
        return I.merge_window(team_cfg(f"change_windows:\n  allow_only: '{cron}'\n"), at)

    def test_a_cron_with_both_day_fields_matches_either(self) -> None:
        # the 5th of the month or a Monday; NOW is Wednesday the 4th
        w = self.cron_at("* * 5 * 1", NOW)
        assert w.until == dt.datetime(2026, 11, 5, tzinfo=UTC)
        assert self.cron_at("* * 5 * 1", dt.datetime(2026, 11, 9, 3, tzinfo=UTC)).open  # a Monday
        assert self.cron_at("* * 5 * 1", dt.datetime(2026, 11, 5, 3, tzinfo=UTC)).open  # the 5th

    def test_sunday_is_0_or_7(self) -> None:
        sunday = dt.datetime(2026, 11, 8, 10, tzinfo=UTC)
        for cron in ("* * * * 0", "* * * * 7", "* * * * 5-7"):
            assert self.cron_at(cron, sunday).open, cron
        assert not self.cron_at("* * * * 1-5", sunday).open

    def test_steps_ranges_and_lists(self) -> None:
        assert self.cron_at("*/15 9 * * *", dt.datetime(2026, 11, 4, 9, 30, tzinfo=UTC)).open
        assert not self.cron_at("*/15 9 * * *", dt.datetime(2026, 11, 4, 9, 31, tzinfo=UTC)).open
        assert self.cron_at("0,30 8-10/2 * * *", dt.datetime(2026, 11, 4, 10, 30, tzinfo=UTC)).open
        assert not self.cron_at(
            "0,30 8-10/2 * * *", dt.datetime(2026, 11, 4, 9, 30, tzinfo=UTC)
        ).open

    def test_six_fields_fail_closed(self) -> None:
        assert not self.cron_at("* * * * * *", NOW).open

    def test_an_unknown_reopening_beats_a_known_one(self) -> None:
        cfg = team_cfg(
            "change_windows:\n  allow_only: 'nope'\n  deny:\n"
            "    - {from: '2026-11-04T09:00:00Z', to: '2026-11-04T12:00:00Z', reason: audit}\n"
        )
        w = I.merge_window(cfg, NOW)
        assert (w.open, w.until) == (False, None)
        assert "audit" in (w.reason or "")
        assert "allow_only" in (w.reason or "")

    def test_a_sprint_without_merge_freeze_never_freezes(self) -> None:
        assert I.merge_window(team_cfg("sprint: {cadence: 1w, anchor: 2026-11-02}\n"), NOW).open

    def test_the_clock_must_have_a_time_zone(self) -> None:
        with pytest.raises(ValueError, match="timezone"):
            I.merge_window(team_cfg(), NOW.replace(tzinfo=None))


# --- T11: edits by non-members -----------------------------------------------------------------


class Members:
    def __init__(self, *actors: str) -> None:
        self.actors = set(actors)
        self.asked: list[tuple[str, str]] = []

    def is_member(self, team: str, actor: str) -> bool:
        self.asked.append((team, actor))
        return actor in self.actors


class TestEdits:
    REV = ticket_revision(fields())

    def review(self, f: TicketFields, editor: str | None, members: Members) -> I.EditVerdict:
        return I.review_edit(
            team="team-a", confirmed_revision=self.REV, fields=f, editor=editor, members=members
        )

    def test_an_unchanged_revision_changes_nothing_whoever_wrote_it(self) -> None:
        v = self.review(fields(), MALLORY, Members(ALICE))
        assert (v.action, v.status) == ("unchanged", None)

    def test_a_member_edit_is_accepted_at_once(self) -> None:
        v = self.review(fields("new"), ALICE, Members(ALICE))
        assert (v.action, v.status) == ("accepted", None)
        assert v.revision == ticket_revision(fields("new"))

    def test_a_non_member_edit_pauses_the_run_for_a_member(self) -> None:
        m = Members(ALICE)
        v = self.review(fields("new"), MALLORY, m)
        assert (v.action, v.status) == ("pause", RunStatus.WAITING_HUMAN)
        assert v.revision == ticket_revision(fields("new"))
        assert m.asked == [("team-a", MALLORY)]

    @pytest.mark.parametrize("editor", [None, "", "mallory", "|x", "idp|", " idp|x"])
    def test_an_unknown_editor_pauses_and_is_never_looked_up(self, editor: str | None) -> None:
        m = Members("mallory", "|x", "idp|", " idp|x", "")
        v = self.review(fields("new"), editor, m)
        assert v.action == "pause"
        assert m.asked == []

    def test_a_route_input_edit_by_a_non_member_pauses_too(self) -> None:
        assert self.review(fields(risk="Low"), MALLORY, Members(ALICE)).action == "pause"

    def test_a_member_confirms_a_pending_revision(self) -> None:
        pending = ticket_revision(fields("new"))
        got = I.confirm_edit(
            team="team-a",
            pending_revision=pending,
            current_revision=pending,
            confirmer=ALICE,
            members=Members(ALICE),
        )
        assert got == pending

    def test_a_non_member_cannot_confirm(self) -> None:
        pending = ticket_revision(fields("new"))
        with pytest.raises(I.NotAMemberError):
            I.confirm_edit(
                team="team-a",
                pending_revision=pending,
                current_revision=pending,
                confirmer=MALLORY,
                members=Members(ALICE),
            )

    def test_a_confirmation_of_an_older_revision_is_refused(self) -> None:
        with pytest.raises(I.StaleConfirmationError):
            I.confirm_edit(
                team="team-a",
                pending_revision=ticket_revision(fields("one")),
                current_revision=ticket_revision(fields("two")),
                confirmer=ALICE,
                members=Members(ALICE),
            )
