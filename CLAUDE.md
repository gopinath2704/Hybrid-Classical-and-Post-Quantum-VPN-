# Hybrid PQ-VPN — Auto-Routing Skill System

This project has three integrated tools. The agent MUST auto-detect the task type and activate the right combination — the user never needs to name a tool or skill manually.

## Tools available

1. **graphify** — knowledge graph at graphify-out/ (query, path, explain commands)
2. **ponytail** — lazy senior dev mode (minimal code via ponytail:ponytail skill)
3. **agent-skills** — structured engineering process (spec, plan, build, test, review, ship)

## Auto-routing rules

On EVERY user request, classify it and follow the matching workflow automatically. Do not ask which tool to use — just use it.

### Asking about the codebase (how does X work, where is Y, what calls Z, explain the architecture)

→ Run `graphify query "<question>"` immediately. Use `graphify path "<A>" "<B>"` for relationships, `graphify explain "<concept>"` for node details. Fall back to reading source only if the graph doesn't cover it.

### Bug fix (fix, broken, error, crash, failing test, doesn't work, regression)

1. `graphify query` to locate the relevant code and trace the flow
2. Activate ponytail:ponytail skill (full mode) — smallest correct diff at the root cause
3. Grep every caller of the touched function before patching
4. Run `python -m pytest tests/ -x` to verify
5. Run `graphify update .` after the fix

### New feature (add, implement, create, build, new, support, enable)

1. `graphify query` to check if anything similar exists and understand where it fits
2. Activate agent-skills:spec-driven-development — define what to build
3. Activate agent-skills:planning-and-task-breakdown — break into atomic tasks
4. Activate ponytail:ponytail skill (full mode) — code every task minimally
5. Activate agent-skills:incremental-implementation — build one slice at a time
6. Activate agent-skills:test-driven-development — prove each slice works
7. Run `graphify update .` when done

### Refactor / simplify (refactor, simplify, clean up, reduce, too complex, over-engineered)

1. `graphify query` + `graphify explain` to map blast radius and dependencies
2. Activate ponytail:ponytail skill (ultra mode) — maximum simplification
3. Activate agent-skills:code-simplification for structured simplification
4. Run tests to confirm no regressions
5. Run `graphify update .`

### Code review (review, check this, look at, PR, before merge, is this correct)

Run all three perspectives automatically:
1. `graphify query "architectural risks or coupling issues in recent changes"` — structural review
2. Activate ponytail:ponytail-review — is anything over-built?
3. Activate agent-skills:code-review-and-quality — 5-axis: correctness, readability, architecture, security, performance
4. Synthesize into one prioritized list

### Security-related work (crypto, key, handshake, certificate, auth, TLS, quantum, KEM, signature)

This is a post-quantum VPN — security is critical:
1. `graphify query` to understand the security flow
2. Activate agent-skills:security-and-hardening automatically for any crypto/network change
3. Activate ponytail:ponytail (full mode) — minimal code reduces attack surface
4. Run tests + verify no security properties are weakened

### Testing (test, coverage, verify, assert, pytest)

1. `graphify query` to understand what the code under test does
2. Activate agent-skills:test-driven-development
3. Activate ponytail:ponytail (full mode) — minimal test code, no unnecessary fixtures
4. Run `python -m pytest tests/ -x`

### Performance / optimization (slow, performance, benchmark, optimize, latency, throughput)

1. `graphify query` to understand the hot path
2. Activate agent-skills:performance-optimization
3. Activate ponytail:ponytail (full mode) — simplest optimization that works
4. Run benchmarks if they exist (`python benchmarks.py`)

### Documentation (document, explain, ADR, decision record)

1. `graphify query` + `graphify explain` for accurate codebase context
2. Activate agent-skills:documentation-and-adrs
3. Keep docs minimal (ponytail applies to prose too — no essays)

### Debugging (debug, trace, why does, unexpected, investigate)

1. `graphify query` + `graphify path` to trace the flow
2. Activate agent-skills:debugging-and-error-recovery
3. Once root cause found, follow the bug-fix workflow above

### API design (API, endpoint, interface, protocol, message format)

1. `graphify query` to understand existing interfaces
2. Activate agent-skills:api-and-interface-design
3. Activate ponytail:ponytail (full mode) — minimal API surface

## Always-on rules

These apply to EVERY task regardless of type:

- **Graphify first**: before writing any code, query the knowledge graph to understand what exists. Never grep blindly when the graph has the answer.
- **Ponytail always active**: every line of code follows the ladder (YAGNI → reuse → stdlib → platform → dep → one-liner → minimum). Never over-build.
- **Never skip safety**: trust-boundary validation, error handling, security, and accessibility are never on the chopping block — this is a cryptographic VPN.
- **Update graph after changes**: run `graphify update .` after modifying code (also automatic via post-commit hook).
- **Root cause over symptom**: bug fixes grep every caller and fix the shared function once.
