# Phishing Triage - Promptbook Spec (Default)

> **Purpose.** This is a Security Copilot **promptbook** specification for the phishing-triage
> workflow: an ordered set of prompts that build on each other to reach an evidence-backed
> verdict on a user-reported email.
>
> **Important - portal-only.** Security Copilot promptbooks are authored **only in the portal**
> (securitycopilot.microsoft.com). There is **no file/YAML/JSON import and no API**. So this
> document is a spec you recreate by hand, not something the tool can import. Recommended way to
> build it: run the prompts below once in a Security Copilot session, then select them and choose
> **Create promptbook**, reorder if needed, and save.
>
> **Input syntax.** Inputs are placeholder tokens written **in angle brackets with no spaces**
> (e.g. `<INCIDENT_ID>`) directly inside the prompt text. Security Copilot derives the inputs
> from those tokens and prompts the runner for them at run time.
>
> Edit freely. Point the tool at your own copy with `-PromptbookFile` and choose `Append` or
> `Replace`.

---

## Promptbook details (enter these in "Create promptbook")

- **Name:** Phishing Triage - Reported Email
- **Tags:** phishing, triage, email, incident, MDO
- **Description:** Triage a user-reported phishing email end to end - summarize the incident,
  check sender authentication, analyze URLs and attachments, cross-reference Microsoft Threat
  Intelligence, assess recipient exposure, hunt for related messages, and produce an
  evidence-backed verdict with recommended containment.
- **Sharing:** Anyone in my organization (or "Just me" while testing).

## Inputs you'll need

| Token | Required | Description |
|---|---|---|
| `<INCIDENT_ID>` | Required | The Defender/Sentinel incident ID for the reported email. |
| `<NETWORK_MESSAGE_ID>` | Optional | The network message ID of the reported email (from the alert). |
| `<SENDER_ADDRESS>` | Optional | The sender (from/reply-to) address under review. |
| `<RECIPIENT_UPN>` | Optional | The recipient who reported the email. |
| `<FILE_HASH>` | Optional | SHA-256 of any attachment, if present. |

## Prompts (run in this order; each builds on the previous response)

1. Summarize the user-reported phishing incident `<INCIDENT_ID>`. List the reported email's
   sender, reply-to, recipient, subject, timestamp, and how it was reported.

2. For the reported email `<NETWORK_MESSAGE_ID>`, evaluate sender authentication: SPF, DKIM and
   DMARC results and alignment, the sending IP and its reputation. Flag display-name spoofing,
   lookalike/cousin domains, or punycode.

3. Analyze every URL in the reported email. Follow redirects to the final landing domain, give
   the detonation and reputation verdict, and call out credential-harvesting or brand-
   impersonation indicators.

4. Analyze any attachment (hash `<FILE_HASH>`). Provide the detonation verdict, file-hash
   reputation, and any malicious macro/script behavior observed.

5. Cross-reference Microsoft Threat Intelligence for `<SENDER_ADDRESS>`, the URLs, and
   `<FILE_HASH>`. Note any named campaign or threat-actor association and known-bad indicators.

6. Assess recipient exposure for `<RECIPIENT_UPN>`: did they click a link or reply, are there
   sign-in anomalies around the delivery time, and which other mailboxes received the same
   message.

7. Hunt across the tenant for related messages by sender, subject, URL domain, and file hash to
   scope the campaign and list affected recipients.

8. Give a definitive verdict - True Positive (phishing) or False Positive (benign) - with the
   supporting evidence from the steps above and a confidence level. State the single strongest
   reason first.

9. Recommend containment actions (message remediation, Tenant Allow/Block List entries,
   credential reset if harvesting is suspected) and write a concise analyst summary suitable for
   closing the alert.

---

## Per-prompt notes

- Enable **Continue on failure** on prompts 3, 4, and 5 so a missing URL/attachment/TI hit does
  not stop the run.
- Prompts 2, 4, and 6 depend on their tokens; leave the token blank at run time when it does not
  apply (e.g. no attachment) and the step will note it.

*Everything above is a default. Replace tokens/prompts with your organization's specifics, or
maintain your own promptbook file and merge it via the tool.*
