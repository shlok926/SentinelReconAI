# The Production-Readiness Master Prompt
*A reusable prompt + checklist for any SaaS, website, or app build — paste the prompt block at project start (or against existing code for an audit).*

---

## PART A — The Prompt (copy-paste this to Cursor/Claude/any AI assistant)

```
You are helping me build a production-grade application, not a demo or a prototype.
Beyond features, UI, and deployment, I want you to actively design and flag decisions
across the following categories. For anything you skip due to scope/time, tell me
explicitly that you're skipping it and why — don't silently omit it.

1. DATABASE & SCALABILITY
   - Will this schema/query pattern hold up at 10,000+ users, not just 10?
   - Are there indexes on every column used in WHERE, JOIN, and ORDER BY?
   - Is pagination used everywhere instead of loading full tables?
   - Are N+1 query patterns avoided?
   - Is there a plan for what happens when a table goes from hundreds to millions of rows?

2. SECURITY (core)
   - Are passwords hashed with bcrypt/argon2, never stored in plaintext or weak hashing?
   - Are ALL API keys/secrets read from environment variables or a secrets manager —
     NEVER hardcoded, NEVER committed to git, NEVER exposed to the frontend/client?
   - Is every user input validated and sanitized server-side (not just client-side)?
   - Is rate limiting applied on every public endpoint, especially auth and any
     endpoint that calls a paid third-party API?
   - Is RBAC (role-based access control) implemented if there's more than one user role?
   - Is there protection against SQL injection, XSS, and CSRF by default
     (parameterized queries, output escaping, CSRF tokens)?

3. SECRETS & DEPENDENCY MANAGEMENT
   - Is there a .env.example file (not the real .env) committed, with real secrets
     excluded via .gitignore?
   - Are dependencies pinned to specific versions, and is there a plan to run
     `npm audit` / `pip-audit` (or equivalent) regularly or in CI?
   - Are third-party packages reviewed before adding (popularity, maintenance status,
     known CVEs)?

4. AI/LLM-SPECIFIC SECURITY (if this app uses any LLM/AI feature)
   - Is the LLM API key strictly backend-only, never reaching the client?
   - Is there a hard separation between user-supplied content and system-level
     instructions, so a user can't inject text that overrides the AI's behavior
     (prompt injection)?
   - Is there a token/cost cap per user/session to prevent abuse-driven billing spikes?
   - Is AI output treated as advisory and clearly labeled as such, not presented as
     verified fact, especially for anything security-, financial-, or health-related?
   - If the AI can execute or analyze user-submitted code, is that execution sandboxed
     (isolated container, no network access, execution timeout)?

5. MULTI-TENANCY & DATA ISOLATION (if more than one user/org uses this)
   - Is every database query explicitly scoped by tenant_id/user_id — not relying on
     the frontend to "only show" the right data?
   - Has cross-tenant data leakage been explicitly tested (can user A ever see user B's data
     by guessing/incrementing an ID)?
   - Is the most sensitive data table in the app identified, and does it have the
     strongest access control and encryption-at-rest of anything in the system?

6. PERFORMANCE
   - Are pages and APIs measured for load time, not just "it works on my machine"?
   - Is caching used for frequently-read, rarely-changed data (Redis or equivalent)?
   - Is there a plan for what happens during a traffic spike — does it degrade
     gracefully or fall over?

7. MONITORING, LOGGING & ALERTING
   - Are errors logged with enough context to debug without reproducing locally?
   - Is there a basic uptime/error-rate monitor (even a free-tier one)?
   - Will I actually get notified if something breaks, or will I find out from a user?
   - Are logs free of secrets, passwords, and full sensitive payloads?

8. RELIABILITY & DISASTER RECOVERY
   - Are there automated database backups, and have I actually tested restoring one?
   - Can a bad deployment be rolled back quickly?
   - What's the actual recovery time if the database or main service goes down right now?

9. POLICY & COMPLIANCE
   - Is there a Privacy Policy and Terms of Service, even a minimal one, if any user
     data is collected or stored?
   - If storing data about a customer's infrastructure/business (not just their own
     account), is there clarity on data residency and who can access it?
   - Is there a responsible disclosure path (a security contact / security.txt) for
     someone who finds a vulnerability in this app?
   - If something leaks, is there a clear (even if simple) incident response plan —
     who gets notified, how fast, what gets communicated?

10. DEVOPS / CI-CD
   - Does every deploy go through a repeatable pipeline, not manual file copying?
   - Are there separate dev/staging/prod environments, or at minimum separate configs?
   - Are environment variables managed differently and safely across environments?

After reviewing all of the above against this specific project, give me:
(a) a prioritized list of what's actually critical for THIS app given its scope
    (don't pad the list with irrelevant enterprise concerns for a small project),
(b) what you've already handled vs. what's still a gap,
(c) a short "Known Gaps / Security Roadmap" section I can put in my README to be
    transparent about what's intentionally deferred and why.
```

---

## PART B — Why each section matters (for you, not the AI)

**Database & Scalability** — Most portfolio/MVP projects never get tested past a handful of fake users. The first real traffic spike (or interview demo with someone clicking fast) is often the first real load test. Indexes and pagination are cheap to add early, expensive to retrofit.

**Security (core)** — This is the bare minimum any reviewer (recruiter, interviewer, real user) will silently judge you on. A single hardcoded API key found in a public GitHub repo is an instant credibility loss in a technical interview.

**Secrets & Dependency Management** — Supply chain attacks (a compromised npm/pip package) are now one of the most common real-world breach vectors. Pinning versions and auditing isn't paranoia, it's standard practice in 2026.

**AI/LLM-specific security** — This category didn't exist in most "production checklist" content from a few years ago, but it's now core to anything you build, since you consistently build AI-powered tools (Q-Orchestrator, QuantumShield AI Analyst). Prompt injection and cost-abuse are the two failure modes most developers don't think about until it's already happened to them.

**Multi-tenancy & Data Isolation** — The single most common real-world SaaS bug: a missing `WHERE tenant_id = ?` clause that lets User A see User B's data. Worth explicitly testing, not just assuming the ORM handles it.

**Performance** — Users forgive a plain UI. They don't forgive a slow one. This is also one of the easiest things to demonstrate concretely in an interview ("here's how I cut API response time from X to Y").

**Monitoring & Logging** — Without this, you find out about problems from an angry user (or a recruiter who can't get the demo to load), not from your own system.

**Reliability & Disaster Recovery** — A backup you've never tested restoring is not actually a backup, it's a hope.

**Policy & Compliance** — Often the most-skipped category on portfolio projects, but it's exactly the kind of "after launch" thinking that signals seniority — the same instinct behind why you asked this question in the first place.

**DevOps/CI-CD** — Manual deploys eventually cause a 2am mistake. Even a minimal automated pipeline removes one whole class of self-inflicted outages.

---

## How to actually use this (realistic version)

You will not fully build all 10 categories for every solo project on a deadline, and you shouldn't try. The value of this prompt is:

1. **At project start** — paste it so the AI designs with these instincts from the first line of code, instead of bolting security on at the end.
2. **Before a demo/interview/submission** — run it again as an audit prompt against your existing code, and let it generate the "Known Gaps" section honestly. That section, shown to an interviewer, often lands better than a feature list — it shows you understand the difference between "it works" and "it's production-ready."
3. **Pick your real P0s per project.** For a portfolio piece, 2–3 properly-implemented items (secrets management, input validation, one tested backup/restore) beat 10 superficially-mentioned ones.
