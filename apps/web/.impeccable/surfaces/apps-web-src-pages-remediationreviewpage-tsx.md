---
version: 1
slug: "apps-web-src-pages-remediationreviewpage-tsx"
primary_target: "apps/web/src/pages/RemediationReviewPage.tsx"
related_targets: ["apps/web/src/pages/FindingsPage.tsx","apps/web/src/components/FindingDetailPanel.tsx"]
---

Scope: Findings remediation-review workspace. Visitor mode: Operate.

Audience: Security administrators decide whether a proposed Linux configuration change is acceptable; analysts and auditors review the same evidence read-only.

Job And Task: Move from current finding evidence to an accountable, durable approval, rejection, or cancellation record. The primary action changes with plan state and never executes remediation.

Proof And Content: Status queue, source-currentness, observed versus required state, affected paths, restart or reboot impact, requester, version, decision history, and any matching reviewed declarative action with its digest, stop conditions, validation, and rollback sequence.

Constraints: Keep this inside Security Findings; do not add duplicate global navigation. Approval and catalog actions are explicitly non-executable. Admin-only decisions, reasons for rejection and cancellation, keyboard-accessible dialogs, progressive disclosure for procedure detail, and a queue-to-dossier mobile sequence.

Chosen Direction: A warm enterprise change-review desk: compact status rail, searchable plan queue, and an in-page evidence dossier. The memorable moment is the side-by-side state comparison immediately beneath the non-execution lock.

Unresolved Decisions: Execution and rollback workflows remain out of scope until a separately authorized, policy-governed remediation release exists.
