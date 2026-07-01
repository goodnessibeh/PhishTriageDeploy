# PhishTriageDeploy

PowerShell 7 tooling that **stages a Microsoft tenant for the Defender for Office 365
Phishing Triage Agent** and hands off the final, portal-only setup to an operator.

Its authentication and safety model: UPN-based `config/tenants.json`, interactive delegated
OAuth (no stored secrets), a wrong-tenant guard before any write, and **dry-run by default**.

## What it does (and the honest boundary)

The Phishing Triage Agent **cannot be created by any API** — agent creation is a Defender
portal wizard. This tool automates everything up to that step and then prints a precise
handoff checklist. Concretely, per tenant it:

1. Connects to Microsoft Graph and **guards against the wrong tenant**.
2. Confirms the admin holds Entra **Security Administrator**.
3. **License gate** — hard-verifies **MDO Plan 2** via `subscribedSkus` (exits if absent);
   best-effort checks **Security Copilot SCU** capacity (asks to confirm if unreadable).
4. **Identity** — create a dedicated account (you supply the name), select an existing
   agent identity, or skip (portal-created Entra Agent ID).
5. **Permissions** — idempotently reconciles a custom **Defender URBAC** role holding the
   five required permissions and assigns it to the identity.
6. **Runbook + promptbook** — resolves a default/append/replace phishing-triage **runbook**
   and a Security Copilot **promptbook** spec, saving both to your Desktop for the operator
   to apply in the portal.
7. **Prereq report** (drives the handoff readiness flag) + **wizard handoff** checklist.

## Requirements

- PowerShell 7.0+
- `Microsoft.Graph.Authentication` module (auto-installed on first run)
- An admin account with the **Security Administrator** Entra role
- Licenses: **Microsoft Defender for Office 365 Plan 2** and **Security Copilot** (SCU
  capacity)

## Allow scripts to run (Windows)

On Windows, allow local scripts to run (one-time, current user only). Run this in
PowerShell 7:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

`RemoteSigned` lets your local scripts run while still requiring downloaded scripts to be
signed. To allow scripts for the current session only (no persistent change), use instead:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

## Configure

```bash
cp config/tenants.example.json config/tenants.json   # git-ignored
```

Only `UserPrincipalName` is required per tenant; the domain is derived from it.

```json
{ "Tenants": [ { "UserPrincipalName": "admin@contoso.onmicrosoft.com" } ] }
```

Optional per tenant: `IdentityPath` (`ExistingUser`/`NewAgentId`), `AgentAccountUpn`,
`DisplayName`, `SkillsFile`, `SkillsMode` (`Default`/`Append`/`Replace`), and
`PromptbookFile`, `PromptbookMode` for the promptbook spec. Per-tenant values override the
matching CLI defaults.

**No config file?** If `tenants.json` is absent and the session is interactive, the tool
prompts for every field (UPN, identity path, agent account UPN, display name, skills
mode/file), loops for multiple tenants, and offers to save it to `tenants.json` for next
time. Passing `-Tenant admin@contoso.onmicrosoft.com` also works standalone. In a
non-interactive (unattended) run with no config it fails fast instead of hanging.

## Run

```powershell
# Dry-run sweep of every configured tenant (no writes)
./Invoke-PhishingTriageSetup.ps1

# Apply, one tenant, create a named identity
./Invoke-PhishingTriageSetup.ps1 -Live -Tenant admin@contoso.onmicrosoft.com -IdentityMode Create

# Apply, unattended, append a custom skills file
./Invoke-PhishingTriageSetup.ps1 -Live -Force -SkillsMode Append -SkillsFile C:\SOC\triage.md
```

Exit codes: `0` success (manual handoff remains) · `10` wrong tenant · `11` no admin role ·
`20` MDO P2 absent · `21` SCU absent · `22` SCU unconfirmed · `30` write failure.

## The runbook and promptbook

`skills/default-phishing-triage-skills.md` is a managed **runbook** covering whitelists,
custom instructions, analyst insights, evidence-backed verdicts, business-logic /
false-positive reduction, alert search & closure, and Microsoft Threat Intel checks.

`skills/default-phishing-triage-promptbook.md` is a Security Copilot **promptbook** spec
(name, tags, description, `<ANGLE_BRACKET>` inputs, and an ordered prompt sequence) for the
same workflow. Promptbooks are **portal-authored only** (no file import / API), so the spec
is something the operator recreates in Security Copilot.

Point the tool at your own copies and `Append` or `Replace` (`-SkillsFile`/`-SkillsMode`,
`-PromptbookFile`/`-PromptbookMode`). At handoff both are saved to your **Desktop** (paths
shown). They are written even in a dry-run, since they are personal artifacts, not tenant
changes. There is no cloud copy.

> Note: the first-party agent has **no instructions/knowledge API** — it is tuned only by
> portal-typed analyst feedback. This document is therefore a source-of-truth runbook the
> operator applies during handoff (and is manifest-ready for a custom Security Copilot
> agent if one is ever built).

## Layout

```
Invoke-PhishingTriageSetup.ps1   orchestrator
config/                          tenants.json, permissions.json, analyzer settings
src/                             PTCommon, PTLicense, PTIdentity, PTPermissions,
                                 PTPrereqs, PTReport, PTInstructions
skills/                          default runbook + promptbook markdown
tests/                           Pester unit/contract tests
docs/plans/                      design + implementation plan
```

## Develop

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings config/PSScriptAnalyzerSettings.psd1
Invoke-Pester tests/
```

Target: **0 Warnings/0 Errors**, every file under 400 lines.
