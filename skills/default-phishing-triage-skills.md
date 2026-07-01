# Phishing Triage — Skills & Instructions (Default)

> **Purpose.** This is the organization's phishing-triage process document: the default
> skills/instructions the Phishing Triage Agent operation is expected to follow. It is a
> **managed runbook and source-of-truth**, not a file the first-party Defender agent
> ingests automatically — Microsoft's first-party agent is tuned only by portal-typed
> analyst feedback ("lessons"). Use this document to (a) drive the whitelists and feedback
> you seed in the portal, (b) give the SOC a single process reference, and (c) feed the
> Instructions of a custom Security Copilot agent if one is ever built.
>
> Edit freely. Point the tool at your own copy with `-SkillsFile` and choose
> `Append` (merge onto this default) or `Replace` (use yours only).

---

## 1. Organization phishing-triage process (overview)

- **Intake:** alerts originate from user-reported messages ("Email reported by user as
  malware or phish") surfaced in Microsoft Defender. Each becomes a triage item.
- **Goal:** a **definitive, evidence-backed verdict** — True Positive (malicious /
  phishing) or False Positive (benign / expected) — with the minimum analyst effort.
- **Priority order:** confirmed-malicious with active user impact → suspected credential
  harvesting → malware/attachment → spam/graymail → benign.
- **Ownership:** each alert is owned to closure; no alert is left in an ambiguous state.

## 2. Whitelists / allowlists (known-good, reduce false positives)

Maintain these as the authoritative allowlists. Treat matches as strong (not absolute)
benign signals — still confirm intent.

- **Trusted senders / domains:** <add verified partner and internal domains>
- **Trusted sending IPs / infrastructure:** <add known-good mail infrastructure>
- **Sanctioned bulk/marketing senders:** <newsletters, SaaS notifications the org uses>
- **Internal tooling / automated senders:** <ticketing, HR, security tooling addresses>
- **Known-good URLs / link domains:** <internal portals, sanctioned vendors>

> Note: an allowlist hit reduces suspicion but does **not** override clear malicious
> indicators (spoofed display name over an allowlisted domain, lookalike domains, etc.).

## 3. Custom instructions (org-specific rules)

- Follow the org's data-handling and privacy rules when quoting email content.
- Respect regional/regulatory constraints on content access.
- <Add org-specific rules: VIP handling, legal-hold considerations, escalation paths,
  languages/regions of interest, brands most impersonated against this org.>

## 4. Providing insights to analysts

For every triaged alert, give the analyst a concise, skimmable brief:

- **One-line verdict** + confidence.
- **Why** (top 3 signals, plainest first).
- **What to check** if they want to verify (links to the exact evidence).
- **Recommended action** (close as FP / confirm TP + contain / escalate).
- Avoid jargon dumps; lead with the decision, then the proof.

## 5. Definitive verdict with proof (evidence standard)

A verdict must cite **concrete, reproducible evidence**, not intuition:

- **Sender authentication:** SPF / DKIM / DMARC results; alignment; sending IP reputation.
- **Display-name / domain spoofing:** lookalike/cousin domains, punycode, display-name vs
  actual address mismatch.
- **URL analysis:** final landing domain after redirects, detonation result, credential-
  harvesting page indicators, URL reputation / Threat Intel hits.
- **Attachment analysis:** file detonation verdict, hash reputation, macro/scripting.
- **Content cues:** urgency/financial-lure language, brand impersonation, reply-to
  mismatch.
- **Verdict statement format:** `<TP/FP> — <primary reason> — evidence: <list>`.

## 6. Business logic & email-content context analysis (false-positive reduction)

Apply organizational context before finalizing, to avoid closing legitimate mail as phish:

- **Expected business flows:** invoices from known vendors, DocuSign/e-sign from real
  counterparties, HR/payroll cycles, recruiting, calendar invites.
- **Relationship history:** has the org corresponded with this sender/domain before?
- **Content vs claim:** does the ask match a real, expected business process, or is it a
  novel out-of-band request (gift cards, wire changes, credential resets)?
- **Language/tone:** legitimate transactional mail vs manufactured urgency.
- When context strongly indicates legitimate business flow **and** authentication passes
  **and** no malicious URL/attachment → lean False Positive with the context cited.

## 7. Searching & closing alerts

- **Search / hunt:** pivot on sender, subject, URL domain, file hash, and campaign
  indicators to find related messages and scope the blast radius.
- **Correlate:** link the alert to any related incident; note recipients affected.
- **Close:** set classification (True/False Positive) with the evidence-backed reason;
  for confirmed phish, ensure containment actions (see below) are triggered/handed off.
- **One decision per alert**, tied only to the email under review; record the reasoning so
  it can become a portal feedback "lesson."

## 8. Checking Microsoft Threat Intelligence

- Cross-reference sender infrastructure, URLs, and file hashes against **Microsoft Threat
  Intelligence** and advanced-hunting tables.
- Note any named campaign / actor association and known-bad indicators.
- Use TI corroboration to strengthen a verdict; absence of TI hits is not proof of benign.

## 9. Containment & handoff (on confirmed True Positive)

- Remediate/soft-delete matching messages across mailboxes where policy allows.
- Add confirmed-bad senders/domains/URLs to the Tenant Allow/Block List.
- Notify affected users / trigger credential reset if harvesting is suspected.
- Escalate per the org's IR runbook when scope or impact warrants.

---

*Everything above is a default. Replace the bracketed `<...>` placeholders with your
organization's specifics, or maintain your own file and merge it via the tool.*
