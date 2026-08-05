import { Check, Copy, FileCode2, Info, ShieldCheck, SquareTerminal, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { Finding } from '../types'

const pathPattern = /\/(?:[A-Za-z0-9._@%+,=*?-]+\/)*[A-Za-z0-9._@%+,=*?-]+/g

function reportedPaths(finding: Finding) {
  const source = [
    finding.actual,
    finding.expected,
    finding.remediation_summary,
    ...finding.remediation_commands,
    ...finding.verification_commands,
  ].filter(Boolean).join('\n')
  return [...new Set((source.match(pathPattern) ?? []).map((path) => path.replace(/[.,;:)]+$/, '')))]
}

function CommandRow({ command, label }: { command: string; label: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(command)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  return <div className="remediation-command">
    <div className="remediation-command-label"><span>{label}</span><span>Bash</span></div>
    <div className="remediation-command-line">
      <code><span aria-hidden="true">#</span>{command}</code>
      <button type="button" onClick={() => void copy()} aria-label={`Copy ${label.toLowerCase()}`}>
        {copied ? <Check size={15} /> : <Copy size={15} />}
      </button>
    </div>
  </div>
}

export function RemediationGuide({ finding }: { finding: Finding }) {
  const paths = useMemo(() => reportedPaths(finding), [finding])
  const requiresChangeControl = finding.remediation_commands.some((command) =>
    /\b(reboot|shutdown|purge|remove|rm|userdel|groupdel)\b/i.test(command),
  )
  const hasPlaceholders = finding.remediation_commands.some((command) =>
    /\b(?:APPROVED|LEGACY|REPLACE|YOUR|EXAMPLE)_[A-Z0-9_]+\b/.test(command),
  )

  return <section className="remediation-guide" aria-label={`Remediation guide for ${finding.title}`}>
    <header className="remediation-guide-header">
      <div>
        <p className="detail-label">Operator Guide</p>
        <h3>Understand The Change Before Applying It</h3>
        <p>Compare the observed and required states, review the affected files, then apply and verify each command separately.</p>
      </div>
      <span className="remediation-safety-state"><ShieldCheck size={14} />Guided Change</span>
    </header>

    <div className="remediation-state-grid">
      <article className="remediation-state remediation-state-current">
        <span>Current State</span>
        <strong>What LSA Observed</strong>
        <pre>{finding.actual?.trim() || 'The scanner did not report a concrete current value.'}</pre>
      </article>
      <article className="remediation-state remediation-state-required">
        <span>Required State</span>
        <strong>What You Need To Set</strong>
        <pre>{finding.expected?.trim() || 'Use the approved benchmark or local security policy as the target.'}</pre>
      </article>
    </div>

    <div className="remediation-explanation">
      <Info size={17} />
      <div><strong>Why This Setting Is Used</strong><p>{finding.remediation_summary?.trim() || 'This control reduces the host exposure identified by the security benchmark. Review the control with the system owner before changing production configuration.'}</p></div>
    </div>

    <ol className="remediation-steps">
      <li>
        <span className="remediation-step-number">1</span>
        <div className="remediation-step-content">
          <h4>Review The Files And Protect Recovery Access</h4>
          <p>Confirm the host is in scope and preserve a recovery path. Back up each file you plan to edit using your approved change procedure.</p>
          {paths.length ? <div className="remediation-file-list">{paths.map((path) => <code key={path}><FileCode2 size={14} />{path}</code>)}</div> : <p className="remediation-empty-note">No fixed configuration path was reported for this control. The setting may be runtime-managed, package-managed, or dependent on local policy.</p>}
        </div>
      </li>
      <li>
        <span className="remediation-step-number">2</span>
        <div className="remediation-step-content">
          <h4>Apply The Required Configuration</h4>
          {finding.remediation_commands.length ? <>
            <p>Open an approved root shell, then run one command at a time. Review paths, package names, and command output before continuing.</p>
            <CommandRow command="sudo -i" label="Open Root Shell" />
            {finding.remediation_commands.map((command, index) => <CommandRow key={`${index}:${command}`} command={command} label={`Apply Step ${index + 1}`} />)}
          </> : <p className="remediation-empty-note">This control does not provide a safe universal command. Apply the required state through your configuration-management system or follow the platform-specific guidance above.</p>}
          {(requiresChangeControl || hasPlaceholders || finding.reboot_required || finding.service_restart) && <div className="remediation-warning"><TriangleAlert size={16} /><div><strong>Operational Review Required</strong><ul>{hasPlaceholders && <li>Replace command placeholders with approved values before execution.</li>}{requiresChangeControl && <li>The proposed change can remove software, accounts, or restart the host. Use change control.</li>}{finding.service_restart && <li>A service restart is required and may interrupt active sessions.</li>}{finding.reboot_required && <li>A controlled reboot is required to complete this remediation.</li>}</ul></div></div>}
        </div>
      </li>
      <li>
        <span className="remediation-step-number">3</span>
        <div className="remediation-step-content">
          <h4>Verify The Effective State</h4>
          <p>Run the verification commands after the change. Confirm their output matches the required state, then run a new LSA audit.</p>
          {finding.verification_commands.length ? finding.verification_commands.map((command, index) => <CommandRow key={`${index}:${command}`} command={command} label={`Verify Step ${index + 1}`} />) : <div className="remediation-empty-note flex items-center gap-2"><SquareTerminal size={15} />No separate verification command was reported. Re-run the LSA audit and confirm the finding closes.</div>}
        </div>
      </li>
    </ol>
  </section>
}
