# Phishing Triage Agent Deployment Tool — Design

**Date:** 2026-07-01
**Status:** Approved design (brainstorming complete)
**Author:** Goodness Caleb Ibeh

---

## 1. Purpose

A PowerShell 7 tool that **stages a tenant for the Microsoft Defender for Office 365
(MDO) Phishing Triage Agent** end-to-end: verifies the required licenses/subscriptions
(and exits cleanly if absent), creates or selects the agent identity, and assigns the
five required Defender Unified RBAC (URBAC) permissions — then hands off the final,
portal-only setup step to a human operator.

Its authentication and safety idioms: interactive delegated OAuth, UPN-based config,
wrong-tenant guard, dry-run by default, idempotent "already exists = success".

---

## 2. The load-bearing constraint (why this is a *stager*, not a one-click installer)

Research against Microsoft Learn (2025–2026) established that the Phishing Triage Agent
**cannot be created programmatically**. There is **no Graph API, PowerShell cmdlet, or
Security Copilot API** to deploy the agent, check whether it is deployed, or bind its
identity. Agent creation is **strictly a portal wizard** at
`security.microsoft.com` → Security Copilot → Agents.

What **is** automatable — and constitutes the bulk of the requirement:

| Requirement | Automatable? | Mechanism |
|---|---|---|
| License / subscription verification (exit if absent) | ✅ Yes | Graph `GET /subscribedSkus` — MDO P2 service plan |
| SCU / Security Copilot capacity check | ⚠️ Best-effort | No Graph endpoint; Azure ARM `Microsoft.SecurityCopilot/capacities`, else confirm |
| Create the identity | ✅ Yes (dedicated-account path) | Graph `POST /users` |
| Assign the 5 permissions | ✅ Yes | Graph **Defender RBAC (beta)** — custom URBAC role + `roleAssignments` |
| Bind identity to agent + finish setup | ❌ Manual | Portal wizard, gated by Entra **Security Administrator** |

**Design consequence:** the tool is a **readiness-checker + identity/permission stager +
guided handoff**, not a headless deployer. This boundary is stated honestly to the
operator at the end of every run.

---

## 3. Key decisions (from brainstorming)

- **Identity path:** *Detect & branch* — support both the dedicated-account path and the
  portal-created Entra Agent ID path.
- **Run model:** *Multi-tenant / MSP, idempotent reconciler* — run per client tenant,
  safe to re-run; asserts state and reports/fixes drift.
- **Stack:** PowerShell 7 + `Microsoft.Graph` module, interactive `Connect-MgGraph`
  (interactive MSAL delegated-OAuth browser sign-in; no stored secrets, tokens in memory).
- **License gate:** MDO Plan 2 is a **hard gate** (`subscribedSkus`). SCU capacity is
  **best-effort ARM check, else confirm** — if detectable and absent → exit; if
  unreadable → prompt operator to confirm before continuing.
- **Identity selection UX:** prompt to *create new* / *select existing* / *skip*.
  - Create → **operator supplies the display name**; UPN local-part is derived from it
    and editable; domain is locked to the connected tenant.
  - Select existing → list **existing Entra Agent IDs only** (paginated), or paste an
    objectId/UPN directly.
- **Conditional Access:** report-only (detect & warn; the tool does not create CA
  policies).

---

## 4. Architecture & execution flow

Gated pipeline — each stage passes, exits, or (for SCU) asks. Nothing downstream runs
until upstream gates clear.

```
Invoke-PhishingTriageSetup.ps1  (orchestrator, -Live/-Force/-WhatIf, -Tenant <upn>)
        │
  0. Connect + wrong-tenant guard (Connect-MgGraph)   ── abort if wrong tenant   (10)
  1. Admin role check (Security Administrator)         ── abort if missing        (11)
  2. LICENSE GATE
        • MDO P2 via subscribedSkus .......... hard exit if absent               (20)
        • SCU via ARM capacity ............... exit (21) / ask (decline → 22)
  3. Identity resolve (interactive: create / select-existing / skip)
        • create        → POST /users (named) + assign perms
        • select-existing (Agent IDs only, paginated / paste id) + assign perms
        • skip          → readiness + handoff only
  4. PERMISSION GATE (create / select paths)
        • ensure custom URBAC role (5 perms, MDO data source)
        • ensure role assignment → identity
  5. Prereq detection (report-only, manual items)
  6. Summary + guided wizard handoff
```

**Two exit classes:** hard stop (no writes, non-zero) vs manual-handoff stop (all
automatable work done, zero, prints checklist).

**Idempotency is per-stage:** every "ensure" reads current state first, treats
"already exists / already assigned" as success, and reports
`created / already-present / drift-fixed`.

---

## 5. Components & file layout

Each `.psm1` stays under the 400-line limit.

```
PhishTriageDeploy/
├── Invoke-PhishingTriageSetup.ps1     # orchestrator: flags, stage sequencing, exit codes
├── config/
│   ├── tenants.json                   # git-ignored: list of tenant UPNs (+ optional prefs)
│   ├── tenants.example.json           # tracked template
│   └── permissions.json               # the 5 URBAC perms → data-source scope (declarative)
├── src/
│   ├── PTCommon.psm1                  # connect, wrong-tenant guard, admin-role check, logging
│   ├── PTLicense.psm1                 # subscribedSkus (MDO P2) + ARM SCU best-effort
│   ├── PTIdentity.psm1                # detect/create/select; POST /users; branch logic
│   ├── PTPermissions.psm1             # URBAC custom role + roleAssignments (Defender beta)
│   ├── PTPrereqs.psm1                 # detect-only: URBAC workload, reported-msgs, alert policy
│   └── PTReport.psm1                  # summary table, drift report, wizard checklist
└── README.md
```

Modules return **result objects** (not just console text) so the orchestrator builds the
final report and decides exit codes.

---

## 6. Tenant config & authentication

`config/tenants.example.json` (tracked; real `tenants.json` is git-ignored):

```json
{
  "Tenants": [
    {
      "UserPrincipalName": "admin@contoso.onmicrosoft.com",
      "IdentityPath": "ExistingUser",
      "AgentAccountUpn": "phishing-triage-agent@contoso.onmicrosoft.com",
      "DisplayName": "Phishing Triage Agent"
    },
    {
      "UserPrincipalName": "admin@fabrikam.onmicrosoft.com",
      "IdentityPath": "NewAgentId"
    }
  ]
}
```

- **`UserPrincipalName`** — admin sign-in UPN; *the only required field*. Domain is derived
  from the part after `@` and drives the wrong-tenant guard.
- **`IdentityPath`** *(optional)* — `ExistingUser` / `NewAgentId` / `Auto` (default:
  prompt interactively).
- **`AgentAccountUpn`, `DisplayName`** *(optional)* — supplying both enables unattended
  (non-interactive) create for MSP batch runs.

Reused idioms: `Get-PTConfig`, `Get-PTDomainFromUpn`, wrong-tenant guard, per-tenant
connect/disconnect loop with a `-Tenant <upn>` filter.

---

## 7. Interactive identity resolution

```
Identity for the Phishing Triage Agent:
  [1] Create a new dedicated identity + assign the 5 permissions   (recommended)
  [2] Select an existing agent identity + assign the 5 permissions
  [3] Skip (new Entra Agent ID via the portal wizard — readiness only)
```

**[1] Create** (dedicated Entra account — the only path where the 5 perms can be
pre-assigned):
```
  Display name for the new identity: Phishing Triage Agent      # required, operator-supplied
  Sign-in name (UPN) [phishing-triage-agent@contoso.onmicrosoft.com]:   # local part editable, domain locked
```
`POST /users`: enabled, generated strong password, `forceChangePasswordNextSignIn=false`,
long/no expiry. Idempotent on existing UPN. Skipped when config supplies `DisplayName` +
`AgentAccountUpn`.

**[2] Select existing — Entra Agent IDs only:**
```
Search identities (blank = list all, or paste an objectId/UPN directly): eng
  #   Display name          ObjectId
  1   Eng Triage Agent      8f2a…-…c1
  … page 1/4 …
[#]=select  [N]ext  [P]rev  [F]ilter  paste an ID  [Q]uit:
```
Server-side paging; paste-an-id short-circuits and validates with a single `GET`.
*Caveat:* enumerating Entra Agent IDs is a newer/beta Graph surface — if listing proves
unreliable, the paste-an-id fallback keeps selection working.

**[3] Skip** — no writes; prereq report + wizard handoff only.

---

## 8. Permission model (core)

The 5 permissions are **Defender URBAC** (Security operations group), assigned via a
custom role scoped to the **MDO data source** — *not* Graph app-roles, *not* Entra
directory roles. Declared in `config/permissions.json`:

```json
{
  "RoleName": "Phishing Triage Agent",
  "DataSource": "Microsoft Defender for Office 365",
  "Permissions": [
    { "name": "Security data basics", "level": "read" },
    { "name": "Alerts", "level": "manage" },
    { "name": "Security Copilot", "level": "read" },
    { "name": "Email & collaboration metadata", "level": "read" },
    { "name": "Email & collaboration content: Emails associated with alerts", "level": "read" }
  ]
}
```

> Note: the content permission is the scoped variant **"Emails associated with alerts
> (read)"**, not blanket content access.

**Reconciliation (idempotent) in `PTPermissions`, against Defender RBAC beta endpoints:**
1. **Ensure role** — `roleManagement/defender/roleDefinitions`: create if absent, patch
   if drifted, `[OK]` if matching.
2. **Ensure assignment** — `roleManagement/defender/roleAssignments`: bind role → chosen
   identity objectId; create if absent.
3. **Verify** — read back, diff declared-vs-actual, emit drift report.

All steps honor `-WhatIf`/dry-run and report `created / already-present / drift-fixed`.

---

## 9. Error handling & exit codes

| Code | Meaning |
|---|---|
| `0`  | Automatable work done; agent creation/binding remains manual (expected success) |
| `10` | Wrong tenant — connected tenant ≠ config UPN domain (no writes) |
| `11` | Signed-in admin lacks Security Administrator |
| `20` | MDO Plan 2 absent — hard license gate |
| `21` | SCU confirmed absent via ARM |
| `22` | SCU unreadable and operator declined to continue |
| `30` | Graph/RBAC write failure after retries |

- **Dry-run by default**; writes only under `-Live`/`-Execute`.
- **Transient Graph errors** (429/503) → retry with backoff honoring `Retry-After`;
  permanent errors (403/400) → fail clean with the Graph error body.
- **Per-tenant isolation** in a sweep: one tenant's hard-stop is recorded and the loop
  continues; final roll-up reports per-tenant outcomes.

**Prereq detection (report-only)** — URBAC workload activation, "Monitor reported
messages in Outlook", the "Email reported by user as malware or phish" alert policy on,
the auto-resolve tuning rule off. Unreadable states are listed as **"verify in portal"**.

**Wizard handoff** — on success, a numbered checklist: portal path, which identity to
select (name + objectId), and the Security Administrator reminder.

---

## 10. Testing

- **Unit (Pester, no network):** domain derivation, config parsing, UPN sanitizer,
  wrong-tenant guard comparison, license verdict logic (canned `subscribedSkus`),
  permission drift diff, exit-code mapping.
- **Contract (mocked Graph):** assert correct endpoints/bodies (role create carries
  exactly the 5 perms; retry honors `Retry-After`).
- **Integration (opt-in, disposable tenant):** full dry-run (zero writes), then `-Live`
  run asserting **idempotency — run twice, second run all `[OK] already present`, zero
  drift**.
- **Static:** `PSScriptAnalyzer` (repo settings), `#Requires -Version 7.0`,
  400-line-per-file limit in CI.

---

## 11. Open items to resolve at implementation time

- Exact Graph **beta** endpoint/shape for enumerating **Entra Agent IDs** (fallback:
  paste-an-id).
- Exact Defender URBAC **permission identifiers** in `roleDefinitions` payloads (map the
  five human names to their API representation).
- Whether SCU capacity is readable via ARM in target tenants (drives how often the
  "confirm" branch fires).
- Resolve the MDO P2 service-plan GUID at runtime from Microsoft's licensing CSV rather
  than hardcoding.

---

## References

- Phishing Triage Agent: https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent
- Deploy AI agents in Defender: https://learn.microsoft.com/en-us/defender-xdr/security-copilot-agents-defender
- Entra Agent ID: https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id
- Defender URBAC: https://learn.microsoft.com/en-us/defender-xdr/manage-rbac ,
  https://learn.microsoft.com/en-us/defender-xdr/custom-permissions-details
- Graph Defender RBAC role assignment (beta):
  https://learn.microsoft.com/en-us/graph/api/rbacapplicationmultiple-post-roleassignments?view=graph-rest-beta
- Security Copilot inclusion / SCUs:
  https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion
- Licensing service plan reference:
  https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
