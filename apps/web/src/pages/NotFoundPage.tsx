import { ArrowRight, Compass, House, MagnifyingGlass } from '@phosphor-icons/react'
import { Link, useLocation } from 'react-router-dom'

export function NotFoundPage() {
  const location = useLocation()
  return <div className="page-reveal not-found-page">
    <section className="not-found-content">
      <div className="not-found-code">404</div>
      <span className="not-found-icon"><Compass size={26} weight="duotone" /></span>
      <p className="section-label">Unknown Console Location</p>
      <h1>This Page Does Not Exist</h1>
      <p>The address <code>{location.pathname}</code> does not match a current LSA workspace. Use a known destination or search the console.</p>
      <div className="not-found-actions">
        <Link to="/" className="button-primary"><House size={15} />Security Overview</Link>
        <Link to="/hosts" className="button-secondary"><MagnifyingGlass size={15} />Browse Assets</Link>
      </div>
      <nav aria-label="Suggested destinations">
        <Link to="/findings">Security Findings <ArrowRight size={13} /></Link>
        <Link to="/applications">Applications <ArrowRight size={13} /></Link>
        <Link to="/evidence">Evidence Intake <ArrowRight size={13} /></Link>
      </nav>
    </section>
  </div>
}
