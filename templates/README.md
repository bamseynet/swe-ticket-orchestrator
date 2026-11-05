# Bundled templates

`standard` is the workflow template. `kanban` and `regulated` are overlays on it
(`extends: standard@1`). Each folder has a README saying when to use it and which checks to
require. `org-policy.yaml` is a synthetic example `OrgPolicy` that all three validate against.

| Folder | File | Kind | Use it for |
|---|---|---|---|
| [`standard/`](standard/README.md) | `workflow.yaml` | `Workflow` (template) | Review and QA before merge. A Scrum team needs only this |
| [`kanban/`](kanban/README.md) | `overlay.yaml` | `WorkflowOverlay` | Trunk-based flow: merge after review, QA on staging, then release |
| [`regulated/`](regulated/README.md) | `overlay.yaml` | `WorkflowOverlay` | Extra gates for security and change approval, with no carry-over |

The files are the PLAN.md section 7.6 to 7.8 examples. `tests/config/test_templates.py` fails if
they drift from PLAN.md, and runs every one through the real loaders and validators (V1 to V17).
The PLAN's `payments-scrum` overlay is a team example, not bundled. The overlays' `intake` and
`repo` are placeholders: replace them with your team's own. Nothing here is real.
