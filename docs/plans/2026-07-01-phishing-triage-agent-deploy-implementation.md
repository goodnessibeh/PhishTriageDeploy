# Plan — PhishTriageDeploy implementation

Build the `PhishTriageDeploy` PowerShell 7 tool from its approved design as an idempotent,
multi-tenant reconciler that stages a tenant for the MDO Phishing Triage Agent
(license/identity/URBAC permissions) and hands the portal-only agent creation to an
operator. Modules are built bottom-up (leaf logic before orchestrator) so each is
unit-testable in isolation against mocked Graph, every file under 400 lines, and
PSScriptAnalyzer stays at 0 Warnings/Errors.

## Scope
- **In:** `Invoke-PhishingTriageSetup.ps1` + 6 `src/*.psm1` modules, `config/`, Pester
  tests, analyzer settings, README. License gate, identity create/select, URBAC
  role+assignment, prereq detection (report-only), wizard handoff.
- **Out:** Agent creation/identity-binding (portal wizard, manual), creating Conditional
  Access policies (report-only), any endpoint Microsoft doesn't expose (SCU write,
  agent-deployed check).

## Action items
```
[ ] Scaffold project: git init, tree, analyzer settings, tenants.example.json,
    permissions.json, .gitignore (tenants.json), README.
[ ] PTCommon.psm1: config, domain-from-UPN, Connect-PTGraph, Assert-PTTenant guard,
    Test-PTAdminRole, Invoke-PTGraphRequest (retry), Write-PTStatus. Unit-test helpers.
[ ] PTLicense.psm1: MDO P2 verdict from subscribedSkus (hard gate) + best-effort ARM SCU
    with confirm-fallback. Unit-test verdict logic.
[ ] PTIdentity.psm1: interactive resolver (create/select/skip), New-PTAgentUser, agent-ID
    list + paste-an-id. Unit-test sanitizer + branch.
[ ] PTPermissions.psm1: idempotent URBAC role + assignment via Defender RBAC beta + drift
    diff. Contract-test payloads; unit-test drift classification.
[ ] PTPrereqs.psm1: report-only prereq detection. Unit-test report shaping.
[ ] PTReport.psm1: summary, drift report, wizard handoff checklist.
[ ] Invoke-PhishingTriageSetup.ps1: flags, per-tenant loop, exit-code map. Unit-test map.
[ ] Pester tests + opt-in integration (dry-run zero-writes; -Live run-twice idempotency).
[ ] CI/local gate: PSScriptAnalyzer 0 Warn/Err, 400-line check, Pester; finish README.
```

## Open questions
- Exact Defender RBAC beta payload shape for the five URBAC permission identifiers.
- Whether Entra Agent ID enumeration has a reliable beta Graph collection yet.
- Target CI host (GitHub Actions vs local pre-commit).
