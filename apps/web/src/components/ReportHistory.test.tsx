import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { ReportHistory } from './ReportHistory'

vi.mock('../api/client', () => ({
  api: {
    compareReport: vi.fn(),
    downloadArtifact: vi.fn(),
    reports: vi.fn(),
  },
}))

beforeEach(() => {
  vi.mocked(api.reports).mockResolvedValue([{
    id: 'report-1',
    host_id: 'host-1',
    generated_at: '2026-08-02T08:30:00Z',
    received_at: '2026-08-02T08:31:00Z',
    scanner_version: '0.3.0',
    profile: 'production_server',
    modules: ['cis'],
    summary: {},
    compliance_score: 95,
    security_score: 91,
    artifact_name: 'report.zip',
    artifact_size_bytes: 2048,
    artifact_stored_at: '2026-08-02T08:31:00Z',
    artifact_retention_until: '2027-08-02T08:31:00Z',
    artifact_available: true,
    signing_key_id: 'key-1',
    signature_verified: true,
    finding_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  }])
  vi.mocked(api.downloadArtifact).mockResolvedValue({
    blob: new Blob(['evidence']),
    filename: 'report.zip',
    checksum: 'sha256',
  })
  vi.stubGlobal('URL', {
    createObjectURL: vi.fn(() => 'blob:evidence'),
    revokeObjectURL: vi.fn(),
  })
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
})

it('downloads integrity-verified vaulted evidence', async () => {
  render(<ReportHistory hostId="host-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Evidence' }))
  await waitFor(() => expect(api.downloadArtifact).toHaveBeenCalledWith('report-1'))
  expect(URL.createObjectURL).toHaveBeenCalled()
})
