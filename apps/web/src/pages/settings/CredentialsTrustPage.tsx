import { Fingerprint, Key } from '@phosphor-icons/react'
import { useSearchParams } from 'react-router-dom'
import { PageHeader } from '../../components/PageHeader'
import { SigningKeysPage } from '../SigningKeysPage'
import { TokensPage } from '../TokensPage'

type TrustView = 'tokens' | 'signing-keys'

export function CredentialsTrustPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const view: TrustView = searchParams.get('view') === 'signing-keys' ? 'signing-keys' : 'tokens'
  const autoCreateToken = view === 'tokens' && searchParams.get('action') === 'create'

  function selectView(nextView: TrustView) {
    const next = new URLSearchParams(searchParams)
    next.set('view', nextView)
    next.delete('action')
    setSearchParams(next, { replace: true })
  }

  return <div className="page-reveal">
    <PageHeader eyebrow="Credential Governance" title="Credentials & Trust" detail="Control who may submit evidence and which scanner identities the platform trusts to sign it." />
    <section className="panel overflow-hidden" aria-label="Credentials and trust workspace">
      <nav className="credential-trust-tabs" aria-label="Credential type">
        <button className={view === 'tokens' ? 'credential-trust-tab credential-trust-tab-active' : 'credential-trust-tab'} aria-current={view === 'tokens' ? 'page' : undefined} onClick={() => selectView('tokens')}><Key size={17} /><span><strong>Ingestion Tokens</strong><small>Authenticate Evidence Submissions</small></span></button>
        <button className={view === 'signing-keys' ? 'credential-trust-tab credential-trust-tab-active' : 'credential-trust-tab'} aria-current={view === 'signing-keys' ? 'page' : undefined} onClick={() => selectView('signing-keys')}><Fingerprint size={17} /><span><strong>Signing Keys</strong><small>Verify Evidence Provenance</small></span></button>
      </nav>
      <div className="credential-trust-content">
        {view === 'tokens' ? <TokensPage embedded autoCreate={autoCreateToken} /> : <SigningKeysPage embedded />}
      </div>
    </section>
  </div>
}
