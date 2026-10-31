#!/usr/bin/env python3
"""Sync docs/STAGES.md into a GitHub backlog (labels, milestones, issues, project).

Stdlib only; talks to GitHub through the ``gh`` CLI. Idempotent: issues are matched
by the ``[D0-05]`` id prefix in their title and updated in place, never duplicated.

    python3 tools/backlog/sync_issues.py --dry-run
    python3 tools/backlog/sync_issues.py --parse-only     # no network at all
    python3 tools/backlog/sync_issues.py                  # for real

Label rules (kept deliberately simple, see ``infer_*``):
  stage:Dn, size:S|M|L, mode:parallel|serial   straight from STAGES.md
  type:*     guessed from title and declared files
  live       stage is D12/D14 or the title says "live"; otherwise ``offline``
  needs:peter  live issues, plus D0-05 (bot account) and D4-24 (GitHub App)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_REPO = "bamseynet/swe-ticket-orchestrator"
DEFAULT_PROJECT_TITLE = "SWE Ticket Orchestrator"
STAGES_PATH = Path(__file__).resolve().parents[2] / "docs" / "STAGES.md"
SIZES = ("S", "M", "L")
RUNS = ("parallel", "serial")
NEEDS_PETER_IDS = {"D0-05", "D4-24"}
LIVE_STAGES = {"D12", "D14"}
ID_RE = r"D\d+-\d+"
TYPES = ("feature", "test", "infra", "docs", "security")
SLEEP_AFTER_WRITE = 1.0


# ---------------------------------------------------------------- parsing

@dataclass
class Stage:
    id: str
    name: str
    goal: str = ""
    exit_criteria: str = ""
    line: int = 0

    @property
    def title(self) -> str:
        return f"{self.id}: {self.name}"


@dataclass
class Issue:
    id: str
    title: str
    stage: str
    description: str = ""
    ac: list[str] = field(default_factory=list)
    deps: list[str] = field(default_factory=list)
    size: str = ""
    run: str = ""
    files: list[str] = field(default_factory=list)
    wave: int | None = None
    line: int = 0

    @property
    def full_title(self) -> str:
        return f"[{self.id}] {self.title}"


@dataclass
class Doc:
    stages: dict[str, Stage] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def github_slug(heading: str) -> str:
    """GitHub's heading anchor: lowercase, drop punctuation, spaces to hyphens."""
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def split_top_level(s: str, sep: str) -> list[str]:
    """Split on ``sep`` outside backtick spans."""
    parts, cur, in_code = [], [], False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "`":
            in_code = not in_code
        if not in_code and s.startswith(sep, i):
            parts.append("".join(cur))
            cur = []
            i += len(sep)
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def parse_ac(text: str) -> list[str]:
    items = split_top_level(text, ";")
    return [i[:-1].rstrip() if i.endswith(".") else i for i in items]


def _para(lines: list[str], start: int) -> str:
    """Text from lines[start] until a blank line or the next bold field line."""
    out = [lines[start]]
    for ln in lines[start + 1:]:
        if not ln.strip() or re.match(r"\*\*[A-Z][^*]*:\*\*", ln) or ln.startswith(("#", "<!--", "|")):
            break
        out.append(ln)
    return "\n".join(out)


def parse(text: str) -> Doc:
    doc = Doc()
    lines = text.split("\n")
    n = len(lines)

    # stages
    stage_idx: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        m = re.match(r"^## (D\d+): (.+?)\s*$", ln)
        if m:
            stage_idx.append((i, m.group(1)))
            doc.stages[m.group(1)] = Stage(m.group(1), m.group(2), line=i + 1)
    for k, (i, sid) in enumerate(stage_idx):
        end = stage_idx[k + 1][0] if k + 1 < len(stage_idx) else n
        # a following non-stage "## " (e.g. Traceability) also ends the section
        for j in range(i + 1, end):
            if lines[j].startswith("## "):
                end = j
                break
        st = doc.stages[sid]
        for j in range(i + 1, end):
            m = re.match(r"^\*\*Goal:\*\*\s*(.*)", lines[j])
            if m and not st.goal:
                st.goal = re.sub(r"^\*\*Goal:\*\*\s*", "", _para(lines, j))
            m = re.match(r"^\*\*Exit criteria:\*\*\s*(.*)", lines[j])
            if m and not st.exit_criteria:
                st.exit_criteria = re.sub(r"^\*\*Exit criteria:\*\*\s*", "", _para(lines, j))
        if not st.goal:
            doc.warnings.append(f"{sid}: no **Goal:** found")
        if not st.exit_criteria:
            doc.warnings.append(f"{sid}: no **Exit criteria:** found")

    # waves
    waves: dict[str, int] = {}
    for i, ln in enumerate(lines):
        m = re.match(r"^<!-- waves:(D\d+) -->", ln)
        if not m:
            continue
        j = i + 1
        while j < n and lines[j].startswith("|"):
            cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
            if cells and cells[0].isdigit():
                for iid in re.findall(ID_RE, " ".join(cells[1:])):
                    if iid in waves:
                        doc.warnings.append(f"{iid}: listed in more than one wave row")
                    waves[iid] = int(cells[0])
            j += 1

    # issues
    heads = [(i, m) for i, ln in enumerate(lines) if (m := re.match(rf"^#### ({ID_RE}): (.+?)\s*$", ln))]
    seen: set[str] = set()
    for k, (i, m) in enumerate(heads):
        iid, title = m.group(1), m.group(2)
        end = heads[k + 1][0] if k + 1 < len(heads) else n
        for j in range(i + 1, end):
            if re.match(r"^(---\s*$|## |#### |<!-- waves)", lines[j]):
                end = j
                break
        stage = iid.split("-")[0]
        if stage not in doc.stages:
            doc.warnings.append(f"{iid}: stage {stage} has no '## {stage}:' section")
        if iid in seen:
            doc.warnings.append(f"{iid}: duplicate issue id")
        seen.add(iid)
        # the issue must sit inside its own stage section
        owner = [sid for si, sid in stage_idx if si < i]
        if owner and owner[-1] != stage:
            doc.warnings.append(f"{iid}: appears under section {owner[-1]}")
        body = lines[i + 1:end]
        ac_i = next((x for x, ln in enumerate(body) if ln.startswith("**AC:**")), None)
        if ac_i is None:
            doc.warnings.append(f"{iid}: no **AC:** line")
            continue
        desc = "\n".join(body[:ac_i]).strip()
        ac_text = body[ac_i][len("**AC:**"):].strip()
        issue = Issue(iid, title, stage, desc, parse_ac(ac_text), line=i + 1)
        if not desc:
            doc.warnings.append(f"{iid}: empty description")
        if not issue.ac:
            doc.warnings.append(f"{iid}: empty acceptance criteria")
        meta = next((ln for ln in body[ac_i + 1:] if ln.startswith("**Deps:**")), None)
        if meta is None:
            doc.warnings.append(f"{iid}: no **Deps:** line")
        else:
            dm = re.match(r"\*\*Deps:\*\*\s*(.*?)\.\s*\*\*Size:\*\*\s*(\S+?)\.\s*\*\*Run:\*\*\s*(\S+?)\.\s*\*\*Files:\*\*\s*(.*)$", meta)
            if not dm:
                doc.warnings.append(f"{iid}: cannot parse Deps/Size/Run/Files line")
            else:
                deps_s, issue.size, issue.run, files_s = dm.groups()
                issue.deps = [] if deps_s.strip().lower() == "none" else re.findall(ID_RE, deps_s)
                if deps_s.strip().lower() != "none" and not issue.deps:
                    doc.warnings.append(f"{iid}: unreadable deps {deps_s!r}")
                issue.files = re.findall(r"`([^`]+)`", files_s)
                if not issue.files:
                    doc.warnings.append(f"{iid}: no files declared")
                if issue.size not in SIZES:
                    doc.warnings.append(f"{iid}: unknown size {issue.size!r}")
                if issue.run not in RUNS:
                    doc.warnings.append(f"{iid}: unknown run mode {issue.run!r}")
        if iid in waves:
            issue.wave = waves[iid]
        else:
            doc.warnings.append(f"{iid}: not in any wave table")
        doc.issues.append(issue)

    ids = {i.id for i in doc.issues}
    for iss in doc.issues:
        for d in iss.deps:
            if d not in ids:
                doc.warnings.append(f"{iss.id}: depends on unknown issue {d}")
            if d == iss.id:
                doc.warnings.append(f"{iss.id}: depends on itself")
    for iid in waves:
        if iid not in ids:
            doc.warnings.append(f"{iid}: in a wave table but has no issue section")
    return doc


# ---------------------------------------------------------------- inference

def infer_type(i: Issue) -> str:
    t = i.title.lower()
    files = i.files
    if re.search(r"secret|hostile|supply chain|threat|redaction|deny list|rotation|browser security|separation of duties", t):
        return "security"
    if files and all(f.startswith("docs/") or f.endswith(".md") for f in files) or re.search(r"\bdocs\b|contribution rules|release checklist|close out|runbook", t):
        return "docs"
    if files and all(f.startswith("tests/") for f in files) or re.search(r"suite|\btests?\b|conformance|soak|corpus|end to end|rehearsal|chaos|scale|journey|verify|verification|eval set|simulator", t):
        return "test"
    if files and all(f.startswith(("infra/", ".github/", "deploy/", "docker")) or "/infra/" in f for f in files) or re.search(r"\bstack\b|deploy|\bci\b|cdk|synth|bootstrap|spike|cost guard|ruleset|images?\b", t):
        return "infra"
    return "feature"


def infer_live(i: Issue) -> bool:
    if i.stage in LIVE_STAGES:
        return True
    # "Live updates hook" / "Live nudge" are UI features, not live-service suites
    return bool(re.search(r"\blive\b", i.title, re.I)) and not re.match(r"live (updates|nudge)", i.title, re.I)


def labels_for(i: Issue) -> list[str]:
    live = infer_live(i)
    out = [f"stage:{i.stage}", f"size:{i.size}", f"type:{infer_type(i)}", f"mode:{i.run}",
           "live" if live else "offline"]
    if live or i.id in NEEDS_PETER_IDS:
        out.append("needs:peter")
    return out


def label_color(name: str) -> str:
    if name.startswith("stage:"):
        return "1d76db"
    if name.startswith("size:"):
        return "c5def5"
    if name.startswith("type:"):
        return "5319e7"
    if name == "mode:serial":
        return "d93f0b"
    if name == "mode:parallel":
        return "0e8a16"
    if name == "needs:peter":
        return "fbca04"
    if name == "live":
        return "b60205"
    return "bfdadc"


MANAGED_PREFIXES = ("stage:", "size:", "type:", "mode:")
MANAGED_EXACT = {"needs:peter", "live", "offline"}


def is_managed(label: str) -> bool:
    return label in MANAGED_EXACT or label.startswith(MANAGED_PREFIXES)


# ---------------------------------------------------------------- bodies

def stages_url(repo: str, anchor: str = "") -> str:
    return f"https://github.com/{repo}/blob/main/docs/STAGES.md" + (f"#{anchor}" if anchor else "")


def render_body(i: Issue, doc: Doc, repo: str, refs: dict[str, int], old_body: str = "") -> str:
    checked = set(re.findall(r"^- \[[xX]\] (.+)$", old_body, re.M))
    ac = "\n".join(f"- [{'x' if a in checked else ' '}] {a}" for a in i.ac)
    deps = ", ".join(f"#{refs[d]} ({d})" if d in refs else d for d in i.deps) or "none"
    files = ", ".join(f"`{f}`" for f in i.files)
    st = doc.stages.get(i.stage)
    stage = st.title if st else i.stage
    wave = f", wave {i.wave}" if i.wave is not None else ""
    link = stages_url(repo, github_slug(f"{i.id}: {i.title}"))
    return (
        f"{i.description}\n\n"
        f"## Acceptance criteria\n{ac}\n\n"
        f"## Details\n"
        f"- **Files:** {files}\n"
        f"- **Size:** {i.size}\n"
        f"- **Mode:** {i.run}\n"
        f"- **Stage:** {stage}{wave}\n"
        f"- **Spec:** [STAGES.md, {i.id}]({link})\n\n"
        f"Depends on: {deps}\n\n"
        f"_Standing acceptance criteria in STAGES.md apply to every issue. This body is generated by "
        f"`tools/backlog/sync_issues.py`; edit the spec, not this text._\n"
    )


def milestone_description(st: Stage, repo: str) -> str:
    return (f"**Goal:** {st.goal}\n\n**Exit criteria:** {st.exit_criteria}\n\n"
            f"Spec: {stages_url(repo, github_slug(f'{st.id}: {st.name}'))}")


# ---------------------------------------------------------------- gh wrapper

class GH:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self.writes = 0

    def run(self, args: list[str], stdin: str | None = None, write: bool = False) -> str:
        if write and self.dry_run:
            return ""
        delay = 30.0
        for attempt in range(7):
            p = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True)
            if p.returncode == 0:
                if write:
                    self.writes += 1
                    time.sleep(SLEEP_AFTER_WRITE)
                return p.stdout
            err = p.stderr + p.stdout
            if re.search(r"\b(403|429)\b|rate limit|secondary|abuse|retry", err, re.I) and attempt < 6:
                print(f"  rate limited, sleeping {delay:.0f}s: {err.strip()[:120]}", file=sys.stderr)
                time.sleep(delay)
                delay = min(delay * 2, 300)
                continue
            raise RuntimeError(f"gh {' '.join(args[:4])} failed: {err.strip()}")
        raise RuntimeError("unreachable")

    def json(self, args: list[str]):
        out = self.run(args)
        return json.loads(out) if out.strip() else None

    def ndjson(self, args: list[str]) -> list:
        return [json.loads(x) for x in self.run(args).splitlines() if x.strip()]


# ---------------------------------------------------------------- sync

@dataclass
class Counts:
    labels: int = 0
    milestones: int = 0
    milestones_updated: int = 0
    issues: int = 0
    issues_updated: int = 0
    project_items: int = 0
    project_created: int = 0
    fields: int = 0
    field_values: int = 0


def sync_labels(gh: GH, repo: str, doc: Doc, c: Counts) -> None:
    existing = {x["name"] for x in gh.json(["label", "list", "-R", repo, "--limit", "1000", "--json", "name"]) or []}
    wanted = sorted({lb for i in doc.issues for lb in labels_for(i)})
    for lb in wanted:
        if lb in existing:
            continue
        print(f"label: create {lb}")
        gh.run(["label", "create", lb, "-R", repo, "--color", label_color(lb)], write=True)
        c.labels += 1


def sync_milestones(gh: GH, repo: str, doc: Doc, c: Counts) -> dict[str, str]:
    """Returns stage id -> milestone title."""
    ms = gh.ndjson(["api", f"repos/{repo}/milestones?state=all&per_page=100", "--paginate", "--jq", ".[]"])
    by_title = {m["title"]: m for m in ms}
    out = {}
    for st in doc.stages.values():
        desc = milestone_description(st, repo)
        out[st.id] = st.title
        m = by_title.get(st.title)
        if m is None:
            print(f"milestone: create {st.title}")
            gh.run(["api", f"repos/{repo}/milestones", "-f", f"title={st.title}", "-f", f"description={desc}"], write=True)
            c.milestones += 1
        elif (m.get("description") or "") != desc:
            print(f"milestone: update {st.title}")
            gh.run(["api", "-X", "PATCH", f"repos/{repo}/milestones/{m['number']}", "-f", f"description={desc}"], write=True)
            c.milestones_updated += 1
    return out


def list_issues(gh: GH, repo: str) -> dict[str, dict]:
    rows = gh.json(["issue", "list", "-R", repo, "--state", "all", "--limit", "2000",
                    "--json", "number,title,body,labels,milestone,url,state"]) or []
    found: dict[str, dict] = {}
    for r in rows:
        m = re.match(rf"^\[({ID_RE})\]", r["title"])
        if not m:
            continue
        if m.group(1) in found:
            print(f"WARNING: duplicate GitHub issues for {m.group(1)}: #{found[m.group(1)]['number']} and #{r['number']}", file=sys.stderr)
            # keep the lowest number
            if r["number"] > found[m.group(1)]["number"]:
                continue
        found[m.group(1)] = r
    return found


def ordered(doc: Doc) -> list[Issue]:
    return sorted(doc.issues, key=lambda i: (int(i.stage[1:]), int(i.id.split("-")[1])))


def sync_issues(gh: GH, repo: str, doc: Doc, ms_titles: dict[str, str], c: Counts) -> dict[str, dict]:
    found = list_issues(gh, repo)
    issues = ordered(doc)
    # phase 1: create missing
    for i in issues:
        if i.id in found:
            continue
        print(f"issue: create {i.full_title}")
        args = ["issue", "create", "-R", repo, "--title", i.full_title, "--body-file", "-",
                "--milestone", ms_titles[i.stage]]
        for lb in labels_for(i):
            args += ["--label", lb]
        out = gh.run(args, stdin=render_body(i, doc, repo, {}), write=True)
        c.issues += 1
        if not gh.dry_run:
            url = out.strip().splitlines()[-1]
            found[i.id] = {"number": int(url.rsplit("/", 1)[1]), "url": url, "title": i.full_title,
                           "body": render_body(i, doc, repo, {}), "labels": [{"name": l} for l in labels_for(i)],
                           "milestone": {"title": ms_titles[i.stage]}, "state": "OPEN"}
    # phase 2: rewrite with resolved numbers; fix drifted title / labels / milestone
    refs = {iid: r["number"] for iid, r in found.items()}
    for i in issues:
        r = found.get(i.id)
        if r is None:
            continue  # dry-run, not yet created
        want_body = render_body(i, doc, repo, refs, r.get("body") or "")
        want_labels = set(labels_for(i))
        have = {l["name"] for l in r.get("labels", [])}
        have_managed = {l for l in have if is_managed(l)}
        args = []
        if (r.get("body") or "").strip() != want_body.strip():
            args += ["--body-file", "-"]
        if r["title"] != i.full_title:
            args += ["--title", i.full_title]
        if want_labels - have:
            args += ["--add-label", ",".join(sorted(want_labels - have))]
        if have_managed - want_labels:
            args += ["--remove-label", ",".join(sorted(have_managed - want_labels))]
        if ((r.get("milestone") or {}).get("title")) != ms_titles[i.stage]:
            args += ["--milestone", ms_titles[i.stage]]
        if not args:
            continue
        print(f"issue: update #{r['number']} {i.id}")
        gh.run(["issue", "edit", str(r["number"]), "-R", repo, *args],
               stdin=want_body if "--body-file" in args else None, write=True)
        c.issues_updated += 1
    return found


def sync_project(gh: GH, repo: str, owner: str, title: str, doc: Doc, found: dict[str, dict], c: Counts) -> str:
    projects = (gh.json(["project", "list", "--owner", owner, "--format", "json", "--limit", "100"]) or {}).get("projects", [])
    proj = next((p for p in projects if p["title"] == title), None)
    if proj is None:
        print(f"project: create {title!r}")
        if gh.dry_run:
            return "(would be created)"
        proj = json.loads(gh.run(["project", "create", "--owner", owner, "--title", title, "--format", "json"], write=True))
        c.project_created += 1
    num = str(proj["number"])
    # link to repo (idempotent: check first)
    q = 'query($o:String!,$n:String!){repository(owner:$o,name:$n){projectsV2(first:50){nodes{number}}}}'
    o, n = repo.split("/")
    linked = gh.json(["api", "graphql", "-f", f"query={q}", "-f", f"o={o}", "-f", f"n={n}"])
    nums = {x["number"] for x in linked["data"]["repository"]["projectsV2"]["nodes"]}
    if proj["number"] not in nums:
        print("project: link to repo")
        gh.run(["project", "link", num, "--owner", owner, "--repo", repo], write=True)

    fields = (gh.json(["project", "field-list", num, "--owner", owner, "--format", "json", "--limit", "100"]) or {}).get("fields", [])
    byname = {f["name"]: f for f in fields}
    stage_ids = sorted(doc.stages, key=lambda s: int(s[1:]))
    if "Stage" not in byname:
        print("project: create field Stage")
        gh.run(["project", "field-create", num, "--owner", owner, "--name", "Stage", "--data-type", "SINGLE_SELECT",
                "--single-select-options", ",".join(stage_ids)], write=True)
        c.fields += 1
    if "Wave" not in byname and any(i.wave is not None for i in doc.issues):
        print("project: create field Wave")
        gh.run(["project", "field-create", num, "--owner", owner, "--name", "Wave", "--data-type", "NUMBER"], write=True)
        c.fields += 1
    if c.fields and not gh.dry_run:
        fields = gh.json(["project", "field-list", num, "--owner", owner, "--format", "json", "--limit", "100"])["fields"]
        byname = {f["name"]: f for f in fields}
    stage_field = byname.get("Stage")
    wave_field = byname.get("Wave")
    stage_opts = {o["name"]: o["id"] for o in (stage_field or {}).get("options", [])}

    items = (gh.json(["project", "item-list", num, "--owner", owner, "--format", "json", "--limit", "1000"]) or {}).get("items", [])
    by_num = {it["content"]["number"]: it for it in items if it.get("content", {}).get("number")}
    pid = proj["id"]
    for i in ordered(doc):
        r = found.get(i.id)
        if r is None:
            print(f"project: would add {i.id}")
            continue
        it = by_num.get(r["number"])
        if it is None:
            print(f"project: add #{r['number']} {i.id}")
            out = gh.run(["project", "item-add", num, "--owner", owner, "--url", r["url"], "--format", "json"], write=True)
            c.project_items += 1
            if gh.dry_run:
                continue
            it = json.loads(out)
        if stage_field and it.get("stage") != i.stage:
            if i.stage in stage_opts:
                gh.run(["project", "item-edit", "--id", it["id"], "--project-id", pid, "--field-id", stage_field["id"],
                        "--single-select-option-id", stage_opts[i.stage]], write=True)
                c.field_values += 1
        if wave_field and i.wave is not None and it.get("wave") != i.wave:
            gh.run(["project", "item-edit", "--id", it["id"], "--project-id", pid, "--field-id", wave_field["id"],
                    "--number", str(i.wave)], write=True)
            c.field_values += 1
    return proj.get("url", "")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--stages", type=Path, default=STAGES_PATH)
    ap.add_argument("--project-title", default=DEFAULT_PROJECT_TITLE)
    ap.add_argument("--dry-run", action="store_true", help="read GitHub, print what would change, write nothing")
    ap.add_argument("--parse-only", action="store_true", help="parse STAGES.md and report; no GitHub access")
    ap.add_argument("--no-project", action="store_true")
    a = ap.parse_args(argv)

    doc = parse(a.stages.read_text())
    for w in doc.warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    print(f"parsed {len(doc.stages)} stages, {len(doc.issues)} issues, {len(doc.warnings)} warnings")
    if a.parse_only:
        return 1 if doc.warnings else 0
    if doc.warnings:
        print("refusing to sync with parse warnings", file=sys.stderr)
        return 1

    owner = a.repo.split("/")[0]
    gh = GH(a.dry_run)
    c = Counts()
    sync_labels(gh, a.repo, doc, c)
    ms = sync_milestones(gh, a.repo, doc, c)
    found = sync_issues(gh, a.repo, doc, ms, c)
    url = ""
    if not a.no_project:
        url = sync_project(gh, a.repo, owner, a.project_title, doc, found, c)
    nums = sorted(r["number"] for iid, r in found.items() if iid in {i.id for i in doc.issues})
    print("\n== summary" + (" (dry run)" if a.dry_run else "") + " ==")
    for k, v in vars(c).items():
        print(f"{k}: {v}")
    if nums:
        print(f"issue numbers: #{nums[0]}..#{nums[-1]} ({len(nums)})")
    if url:
        print(f"project: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
