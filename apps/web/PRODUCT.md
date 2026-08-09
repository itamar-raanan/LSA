# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

LSA serves security engineers, SOC analysts, system administrators, and auditors responsible for Linux fleet posture. Administrators manage identity, evidence trust, agents, groups, policies, and approved operational changes. Analysts investigate assets, applications, vulnerabilities, and security findings. Auditors need read-only access to posture and retained evidence.

## Product Purpose

Linux Security Auditor collects normalized, read-only Linux security evidence through portable offline reports or a managed outbound agent. It correlates hosts, controls, applications, vulnerabilities, policies, and evidence so teams can understand exposure, prioritize work, and document reviewed remediation decisions. Success means an operator can identify what requires attention, understand why, and move through an accountable workflow without losing source evidence or host context.

## Positioning

LSA unifies offline assessment and managed-agent reporting behind the same control and evidence contract. Its remediation path begins with stale-aware, tenant-scoped review records and preserves an explicit separation between approval and host execution.

## Operating Context

The console is used during continuous Linux posture monitoring, finding triage, change review, evidence intake, vulnerability investigation, and security administration. Deployments may be isolated from the internet. Management traffic uses TLS on port 8443; managed agents initiate outbound TLS connections to the restricted agent gateway on port 8444. No inbound host connection or SSH workflow exists.

## Capabilities and Constraints

- Supported collection approaches are signed offline reports and the unified Linux agent.
- Current supported operating-system families include Debian, Ubuntu, and RHEL-compatible systems documented by the repository.
- Findings retain observed state, required state, guidance, verification information, and operational impact.
- Agent groups resolve to one immutable-versioned policy with control-level audit intent.
- The current agent task protocol is allow-listed to audit tasks.
- Remediation plans can be requested, approved, rejected, or canceled, but cannot execute or change a host.
- Newer host evidence makes an earlier plan snapshot stale and blocks its approval.
- Administration mutations require the administrator role; analysts and auditors receive only their authorized views.
- Existing API contracts and offline deployment support must remain intact.

## Brand Commitments

The product name is Linux Security Auditor, shortened to LSA. Product language is calm, direct, operational, and explicit about security boundaries. The established console avoids hacker styling, neon color, decorative gradients, duplicate actions, and controls without function.

## Evidence on Hand

The repository contains the live React console, API schemas, automated tests, scanner control catalog, architecture documentation, report contracts, deployment configuration, and agent implementation. Demo and test records are illustrative; future work must not invent customers, external certifications, or performance claims.

## Product Principles

- Show what is happening, what requires attention, and the next safe action.
- Preserve evidence lineage and tenant isolation across every workflow.
- Prefer progressive disclosure over duplicated metrics or actions.
- Make safety boundaries visible where decisions are made.
- Keep read-only audit and future write-capable remediation as separate trust domains.

## Accessibility & Inclusion

The web console must remain keyboard operable, expose semantic labels and focus states, respect reduced-motion preferences, preserve readable contrast, and adapt to desktop and mobile viewports.
