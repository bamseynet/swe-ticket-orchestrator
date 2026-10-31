# ADR-0012: Sandboxes with no SCM credentials and a minimal role, and private repo access through a broker

**Status:** Accepted

## Context

The PoCs could only read a shallow, unauthenticated clone. This product must read private repos and run tests,
including code a model just wrote, which must be assumed hostile.

## Decision

- **Split agent and code.** Agent logic runs in the agent Runtime, which has Bedrock and Gateway access. Repo code
  runs in a **separate sandbox**, with a minimal role.
- **Default sandbox:** a Runtime per **registered image** (up to 2 GB, ARM64, meeting the service contract), commanded through
  `InvokeAgentRuntimeCommand` (up to 64 KB per command, 1 hour timeout) [S14]. Commands can read that Runtime's role [S61], so it has no data access. Images are registered separately, so publishing a workflow still touches no AWS API.
- **Repo access through a broker** in the control plane, using a narrow App token. It fetches a tarball at a pinned
  SHA (private links expire in 5 minutes [S38]) into a session S3 prefix. The sandbox gets a short presigned URL.
- **Writing goes back as a patch.** The control plane scans it (secrets, paths, size), then commits to `sto/<run>`. Those commits form
  the push receipts that separation of duties relies on.
- **Egress is default-deny,** with a GET-only allowlist proxy in VPC mode, and **Route 53 Resolver DNS Firewall,** because security groups do not filter Amazon DNS [S65]. A host allowlist alone is not a data control, since `npm publish` goes to an allowed host.
- **History** comes from `repo.log` and `repo.blame` tools rather than a full clone.
- **State survives on the branch,** so a dead session loses nothing.

Port: `WorkspaceProvider`, implemented by `local_docker`, `agentcore_sandbox` and `code_interpreter`.

## Alternatives

| Option | Why not |
|---|---|
| Run code in the agent's microVM | A hostile test can read that session's credentials |
| **Code Interpreter as the main workspace** | Supports Python, JS and TS with Sandbox or Public network [S17]. No custom toolchains, so no Java or Go builds. Kept for QA scripts |
| **Git token in the sandbox** | The AWS post recommends a narrow token if one must be present [S25]. Ours avoids it altogether |
| **CodeBuild** | Good for builds, but batch and slow for edit-run loops. Could be a later provider |
| **Session storage for the workspace** | Preview, 1 GB, and resets on version update [S12] |

The QA Browser is one custom browser per team, with `URLBlocklist: ["*"]` and an allowlist for that team's preview wildcard domain, because managed policies are fixed at `CreateBrowser` [S70].

## Consequences

- Teams need an image for their stack. We ship Python, Node, Java and Go base images.
- Sandbox network control and `InvokeAgentRuntimeCommand` behaviour are proven only in D12, so `local_docker` must be a
  faithful stand-in, with no network and the same interface.
- A large repo's tarball can be slow. Sparse snapshots can be added later.
