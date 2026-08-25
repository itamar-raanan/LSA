import {
  ArrowRight, Binoculars, CheckCircle, ClockCounterClockwise, FileArchive,
  HardDrives, Key, LinuxLogo, Network, Package, ShieldCheck, ShieldWarning,
  SquaresFour, UploadSimple, UsersThree,
} from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'

const lifecycle = [
  { title: 'Collect', detail: 'Gather read-only Linux posture and application inventory.' },
  { title: 'Validate', detail: 'Verify identity, scope, checksums, signatures, and report shape.' },
  { title: 'Correlate', detail: 'Connect hosts, controls, software, vulnerabilities, and evidence.' },
  { title: 'Investigate', detail: 'Prioritize exposure and open the affected asset in context.' },
  { title: 'Govern', detail: 'Document decisions without silently changing a host.' },
]

const analystTasks = [
  { icon: SquaresFour, title: 'Start With Overview', detail: 'Review critical findings, affected assets, stale reports, and compliance direction.', to: '/' },
  { icon: ShieldWarning, title: 'Triage Security Findings', detail: 'Filter by severity and category, then compare the observed state with the required state.', to: '/findings' },
  { icon: HardDrives, title: 'Open The Asset Record', detail: 'Confirm operating system, latest posture, applications, finding history, and retained evidence.', to: '/hosts' },
  { icon: Package, title: 'Check Software Exposure', detail: 'Correlate installed versions with locally cached OSV advisories and CISA exploitation priority.', to: '/applications' },
]

export function HowToPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  return <div className="page-reveal how-to-page">
    <header className="how-to-hero">
      <div>
        <h1>How To Use LSA</h1>
        <p>LSA turns read-only Linux evidence into an investigation workspace for analysts, SecOps teams, administrators, and auditors. Start by choosing how systems report, then follow the same evidence path from collection to review.</p>
      </div>
      <nav className="how-to-jump-nav" aria-label="How To sections">
        <a href="#collection">Collect Evidence</a>
        <a href="#investigation">Investigate Risk</a>
        <a href="#features">Understand Features</a>
        <a href="#safety">Know The Boundary</a>
      </nav>
    </header>

    <section className="how-to-lifecycle" aria-labelledby="system-flow-title">
      <div className="how-to-section-heading">
        <div><h2 id="system-flow-title">How The System Works</h2><p>Both collection methods produce the same normalized posture, inventory, and evidence model.</p></div>
      </div>
      <ol>
        {lifecycle.map((step, index) => <li key={step.title}>
          <span>{index + 1}</span>
          <div><strong>{step.title}</strong><p>{step.detail}</p></div>
        </li>)}
      </ol>
    </section>

    <section id="collection" className="how-to-section" aria-labelledby="collection-title">
      <div className="how-to-section-heading">
        <div><h2 id="collection-title">Choose A Collection Workflow</h2><p>The right choice depends on connectivity, installation policy, and reporting frequency—not on the checks you want to see.</p></div>
      </div>
      <div className="collection-switchboard">
        <article>
          <div className="collection-heading"><span><FileArchive size={22} weight="duotone" /></span><div><h3>Offline Ansible Report</h3><p>Best for isolated, air-gapped, occasional, or approval-controlled assessments.</p></div></div>
          <dl className="collection-facts">
            <div><dt>Runs From</dt><dd>Your Ansible controller</dd></div>
            <div><dt>Host Connection</dt><dd>Normal Ansible transport</dd></div>
            <div><dt>LSA Connection</dt><dd>Optional during collection</dd></div>
          </dl>
          <ol className="how-to-steps">
            <li><span>1</span><p>Open Evidence Intake and download the offline scanner ZIP. It includes the scanner, inventory template, runner, checksums, and complete README.</p></li>
            <li><span>2</span><p>{isAdmin ? 'Enroll the host, store its host-scoped ingestion token, and register the scanner public signing key.' : 'Ask an administrator to enroll the host, issue its token, and register the scanner public signing key.'}</p></li>
            <li><span>3</span><p>Edit `inventory.ini`, then run `run-offline.sh` from the extracted package on the Ansible controller.</p></li>
            <li><span>4</span><p>Import the unchanged `lsa-report-*.zip` through Evidence Intake with the host-scoped token.</p></li>
          </ol>
          <Link to="/evidence" className="button-secondary">Download Scanner And Start <ArrowRight size={14} /></Link>
        </article>

        <article>
          <div className="collection-heading"><span><LinuxLogo size={22} weight="duotone" /></span><div><h3>Managed Linux Agent</h3><p>Best for continuous visibility, fleet grouping, scheduled audits, and central policy.</p></div></div>
          <dl className="collection-facts">
            <div><dt>Runs From</dt><dd>Each managed Linux host</dd></div>
            <div><dt>Host Connection</dt><dd>No inbound port or SSH</dd></div>
            <div><dt>LSA Connection</dt><dd>Outbound TCP 8444</dd></div>
          </dl>
          <ol className="how-to-steps">
            <li><span>1</span><p>Create or select a group and review its effective audit policy.</p></li>
            <li><span>2</span><p>Download the DEB, RPM, or universal package and copy the complete enrollment command.</p></li>
            <li><span>3</span><p>Confirm heartbeat health, policy version, and the first accepted audit before expanding deployment.</p></li>
          </ol>
          {isAdmin ? <Link to="/agents" className="button-primary">Open Agents &amp; Groups <ArrowRight size={14} /></Link> : <span className="how-to-permission-note">Ask An Administrator To Enroll Or Move Agents</span>}
        </article>
      </div>
      <div className="collection-common-note"><CheckCircle size={18} weight="fill" /><p><strong>One Evidence Model</strong> Offline and agent reports use the same control logic, application inventory, finding lifecycle, and host history.</p></div>
    </section>

    <section id="investigation" className="how-to-section" aria-labelledby="investigation-title">
      <div className="how-to-section-heading">
        <div><h2 id="investigation-title">A Practical Analyst Workflow</h2><p>Move from fleet signal to source evidence without losing the affected host or current filter context.</p></div>
      </div>
      <div className="analyst-workflow">
        {analystTasks.map(({ icon: Icon, title, detail, to }, index) => <Link key={title} to={to} className="analyst-workflow-step">
          <span className="analyst-step-number">{index + 1}</span>
          <Icon size={20} weight="duotone" />
          <span><strong>{title}</strong><small>{detail}</small></span>
          <ArrowRight size={14} />
        </Link>)}
      </div>
    </section>

    <section id="features" className="how-to-section" aria-labelledby="features-title">
      <div className="how-to-section-heading">
        <div><h2 id="features-title">What You Can Do In LSA</h2><p>Each workspace answers a distinct operational question and links back to the accepted evidence.</p></div>
      </div>
      <div className="feature-directory">
        <article><Binoculars size={20} weight="duotone" /><div><h3>Find What Requires Attention</h3><p>Use Overview and Security Findings to prioritize by severity, lifecycle, category, host, and evidence freshness.</p><Link to="/findings">Review Findings <ArrowRight size={13} /></Link></div></article>
        <article><Package size={20} weight="duotone" /><div><h3>Correlate Applications And CVEs</h3><p>See installed packages and services, affected hosts, vulnerable versions, fixed versions, OSV advisories, and CISA KEV context.</p><Link to="/applications">Review Applications <ArrowRight size={13} /></Link></div></article>
        <article><ClockCounterClockwise size={20} weight="duotone" /><div><h3>Preserve Evidence History</h3><p>Retain original report bundles, verify integrity, compare current posture with earlier reports, and audit evidence actions.</p><Link to="/evidence">Import Evidence <ArrowRight size={13} /></Link></div></article>
        <article><UsersThree size={20} weight="duotone" /><div><h3>Organize The Fleet</h3><p>Assign agents to groups, publish immutable policy versions, select audit controls, and request a bounded audit cycle.</p>{isAdmin ? <Link to="/agents">Manage Fleet <ArrowRight size={13} /></Link> : <span>Administrator Workspace</span>}</div></article>
        <article><Key size={20} weight="duotone" /><div><h3>Control Identity And Trust</h3><p>Administrators manage users, authentication providers, ingestion credentials, signing keys, and management TLS.</p>{isAdmin ? <Link to="/settings">Open Administration <ArrowRight size={13} /></Link> : <span>Administrator Workspace</span>}</div></article>
        <article><UploadSimple size={20} weight="duotone" /><div><h3>Support Connected Or Isolated Sites</h3><p>Use online vulnerability synchronization where permitted, or import scoped intelligence snapshots in air-gapped deployments.</p><Link to="/applications">Review Intelligence State <ArrowRight size={13} /></Link></div></article>
      </div>
    </section>

    <section id="safety" className="how-to-safety" aria-labelledby="safety-title">
      <span><ShieldCheck size={25} weight="duotone" /></span>
      <div>
        <h2 id="safety-title">Know The Current Safety Boundary</h2>
        <p>LSA is audit-only today. Collection reads posture and inventory; agents accept only allow-listed audit tasks. Remediation plans, signed change sets, validation, and recovery-readiness records support review and governance, but they do not write configuration, restart services, restore files, or open a remote shell.</p>
        <div className="safety-facts"><span><Network size={15} /> Agents Initiate Outbound Connections</span><span><ShieldCheck size={15} /> Signed Agent Evidence And Control Responses</span><span><CheckCircle size={15} /> No Hidden Host Changes</span></div>
      </div>
    </section>
  </div>
}
