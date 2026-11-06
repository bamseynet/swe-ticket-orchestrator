# Account bootstrap checklist (D12-00)

Status on 2026-11-06: **partly done.** The worker identity is deliberately limited, so some steps are human-only
and some checks could not be made. Each item says which. No account IDs, ARNs, emails or keys appear here:
`<ACCOUNT_ID>` and `<ALERT_EMAIL>` are placeholders.

## Decisions

- **Region: `us-east-1`.** Peter first chose `eu-west-1` for EU residency, then moved to `us-east-1` on 2026-11-06.
  The reason: the worker's deny policy limits the worker to `us-east-1`, and the CDK bootstrap already exists there.
  EU residency is therefore **not** provided by this deployment. This answers Q4 for the first deploy. Docs and
  examples keep `us.` profiles. Revisit before any pilot with data that must stay in the EU (D14).
- **Identity:** only the `sto-d12` profile (role `sto-d12-worker`) is used, always with `--region us-east-1`
  except for the global Budgets and IAM endpoints.
- **Human-only by design:** the worker's deny policy blocks budget changes (`CostGuardIsHumanOnly`), restricts Regions,
  and denies Marketplace actions. That is intended. Budget changes are made by Peter.

## Checklist

| # | Item | State | Evidence |
|---|---|---|---|
| 1 | Region and residency choice (Q4) | Done: `us-east-1` | Decision above |
| 2 | Anthropic first-time-use form | Done by Peter | Peter, before 2026-11-05 |
| 3 | Bedrock Marketplace agreement, Haiku 5.5 | Done by Peter: AVAILABLE, account-wide | Peter, before 2026-11-05. The worker cannot re-read it (see item 8) |
| 4 | Marketplace agreement, Sonnet 5.5 | **Unknown** | The worker is denied the reads (item 8) |
| 5 | CDK bootstrap in `us-east-1` | **Exists per Peter, not verified by the worker** | `cloudformation:DescribeStacks` and `ssm:GetParameter` on the bootstrap version parameter are denied. Nothing was re-bootstrapped |
| 6 | Project budget `sto-d12-cap` | **Exists, does not match the spec** | See "Budget" below |
| 7 | Three alerts and the $60 budget action | **Pending Peter** | Commands in the PR body, "For Peter to run" |
| 8 | Reads the worker is denied | Recorded | `cloudformation:DescribeStacks` (us-east-1), `ssm:GetParameter` (bootstrap version), `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `budgets:DescribeBudgetActionsForBudget`, `bedrock:GetFoundationModelAvailability`, `bedrock:ListFoundationModelAgreementOffers` |
| 9 | Deny policy shown to work on a throwaway role | **Skipped by Peter's decision 2026-11-06** | No IAM role was created |
| 10 | Budget alarm fires on a test threshold | **Not done** | Needs a second budget, and budget changes are human-only. Peter decides whether to run one |
| 11 | `docs/findings/cost.md` started with the ledger's columns | Done | `docs/findings/cost.md` |
| 12 | Deployed roles have no Marketplace permissions | **Unverified until a deploy** | No stack exists yet. A grep of `infra/lib` and `infra/bin` finds no `aws-marketplace` action. D12-01 re-checks the deployed roles |
| 13 | Checklist committed with no account details | Done | This file |

## Budget

`sto-d12-cap`, read on 2026-11-06 (read-only):

- Limit $75, `TimeUnit` MONTHLY, period starting 2026-11-01 and ending in 2087. Actual spend 0.00, health HEALTHY.
- Three alerts, all state OK, thresholds as **percentages** of $75, with one email subscriber:
  ACTUAL > 50% ($37.50), ACTUAL > 80% ($60), FORECASTED > 100% ($75).
- Spec: one budget for the whole project period, not monthly, with alerts at $25 and $50 actual and $50 forecast,
  and a $60 action that attaches a deny policy for Bedrock and AgentCore invocation to every deployed role.
- Gaps: thresholds differ, there is no $60 action (the worker cannot read actions, so this is unconfirmed), and a
  MONTHLY budget resets each month. If D12 and D14 span a month boundary, the $75 total is not enforced across them.
  Peter decides whether to move to a longer `TimeUnit`.

## Inference profiles in `us-east-1`

From `bedrock list-inference-profiles`, all ACTIVE, 2026-11-06. Free to list.

| Model | `us.` profile | `global.` profile |
|---|---|---|
| Haiku 5.5 | `us.anthropic.claude-haiku-5-5` | `global.anthropic.claude-haiku-5-5` |
| Sonnet 5.5 | `us.anthropic.claude-sonnet-5-5` | `global.anthropic.claude-sonnet-5-5` |
| Opus 5.5 | `us.anthropic.claude-opus-5-5` | `global.anthropic.claude-opus-5-5` |

`us.` and `global.` profiles for the earlier Sonnet 5 and Opus 5 also exist. Which one the catalog uses is decided
under ADR-0014 and verified by D12-02. This issue invoked no model.

## Sonnet 5.5 agreement

Not determined. If Sonnet 5.5 needs its own agreement, Peter accepts it. The worker must not, because Marketplace is
denied to it. To check, Peter runs (as himself):

```sh
aws bedrock get-foundation-model-availability --model-id anthropic.claude-sonnet-5-5 --region us-east-1
aws bedrock list-foundation-model-agreement-offers --model-id anthropic.claude-sonnet-5-5 --region us-east-1
```

If `agreementAvailability` is not AVAILABLE, accept with `aws bedrock create-foundation-model-agreement
--model-id anthropic.claude-sonnet-5-5 --offer-token <TOKEN_FROM_LIST_OFFERS> --region us-east-1`. Both reads are free.
Accepting is a Marketplace subscription and may carry charges, so Peter decides.
