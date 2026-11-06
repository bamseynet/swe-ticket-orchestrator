# D12/D14 cost ledger

The project's AWS spend is capped at $75 in total across D12 and D14 (STAGES.md, D12 "Spend rules").
Before a live session starts, its worker reads this ledger and stops if the session would pass its issue's
cap. One row per session. "Billed" stays blank until billing data shows the cost, which lags by hours.

| Date | Issue | What ran | Cap (USD) | Billed (USD) | Running total (USD) | Notes |
|---|---|---|---|---|---|---|
| 2026-11-05 to 2026-11-06 | D12-00 | Read-only calls: STS, Budgets, CloudFormation, IAM, Bedrock list calls. No resources created, no model invoked. | 1 | 0.00 (budget reported 0.00 actual spend on 2026-11-06) | 0.00 | Billing lag means this is confirmed against Cost Explorer later, not now. |

Expected total across all rows must stay at or below 75.
