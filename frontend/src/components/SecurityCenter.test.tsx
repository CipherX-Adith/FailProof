// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import SecurityCenter from './SecurityCenter'
import { api } from '../lib/api'
import type { SecurityFinding, SecurityScan } from '../types'

vi.mock('../lib/api', () => ({ api: {
  scanSource: vi.fn(), registerScanSource: vi.fn(), securityScans: vi.fn(), securityFindings: vi.fn(), targets: vi.fn(), startSecurityScan: vi.fn(),
  githubStatus: vi.fn(), githubImports: vi.fn(), githubRepositories: vi.fn(), githubBranches: vi.fn(), githubImport: vi.fn(), retryGitHubImport: vi.fn(), removeGitHubImport: vi.fn(),
  aiStatus: vi.fn(), investigations: vi.fn(), patchProposals: vi.fn(), testProposals: vi.fn(), investigate: vi.fn(), generateTestProposals: vi.fn(), testDecision: vi.fn(), executeTestProposal: vi.fn(), generatePatchProposal: vi.fn(), patchDecision: vi.fn(),
} }))

afterEach(() => { cleanup(); vi.clearAllMocks() })

const finding: SecurityFinding = {
  id: 'finding-1', project_id: 'project-1', title: 'Synthetic document ownership mismatch', description: 'A request for Alice returned Bob’s synthetic document.', category: 'authorization', severity: 'high', confidence: 'high', status: 'confirmed', source: 'api_security', scan_type: 'api_security', scanner: 'FailProof deterministic API rule', rule_id: 'demo:readSyntheticDocument:authorization', affected_resource: 'GET /users/{user_id}/documents/{document_id}', cwe_id: null, cve_id: null, remediation: 'Enforce document ownership before returning the record.', references: [], first_detected_at: '2026-10-25T00:00:00Z', last_observed_at: '2026-10-25T00:00:00Z', last_scan_id: 'scan-1', evidence: [{ id: 'evidence-1', scan_id: 'scan-1', evidence_type: 'http-test', details: { response: { requested_by: 'alice', document: { owner: 'bob' } } }, expected_result: 'Return 403 for another user’s document.', actual_result: 'Observed HTTP 200 and a response owner of bob.', relative_path: null, line_number: null, redacted: true, truncated: false, created_at: '2026-10-25T00:00:00Z' }],
}

const blockedScan: SecurityScan = { id: 'scan-blocked', project_id: 'project-1', scan_type: 'dependencies', status: 'blocked', started_at: '2026-10-25T00:00:00Z', completed_at: '2026-10-25T00:00:01Z', scanner_availability: { 'pip-audit': 'unavailable' }, errors: ['pip-audit is not installed.'], warnings: [], configuration: {}, summary: 'Dependency analysis was blocked.', finding_count: 0 }

function respond({ findings = [], scans = [], source = { configured: false, source_name: null, authorized: false, registered_at: null }, targetReady = false }: { findings?: SecurityFinding[]; scans?: SecurityScan[]; source?: { configured: boolean; source_name: string | null; authorized: boolean; registered_at: string | null }; targetReady?: boolean } = {}) {
  vi.mocked(api.scanSource).mockResolvedValue(source)
  vi.mocked(api.securityScans).mockResolvedValue(scans)
  vi.mocked(api.securityFindings).mockResolvedValue(findings)
  vi.mocked(api.targets).mockResolvedValue(targetReady ? [{ id: 'target-1', project_id: 'project-1', name: 'Demo', base_url: 'http://127.0.0.1:8765', spec_source: 'upload', authorized: true, status: 'ready', registered_at: '2026-10-25T00:00:00Z' }] : [])
  vi.mocked(api.githubStatus).mockResolvedValue({ configured: false, connected: false, installations: [], login: null, account: null, app_slug: null, read_only: true, permissions: ['contents:read', 'metadata:read'], message: 'GitHub App integration is not configured on the backend.' })
  vi.mocked(api.githubImports).mockResolvedValue([])
  vi.mocked(api.aiStatus).mockResolvedValue({ available: false, provider: null, model: null, message: 'AI investigation unavailable: configure a provider.' })
  vi.mocked(api.investigations).mockResolvedValue([])
  vi.mocked(api.patchProposals).mockResolvedValue([])
  vi.mocked(api.testProposals).mockResolvedValue([])
}

describe('Security Center', () => {
  it('shows a truthful not-scanned empty state and disables unavailable scan controls', async () => {
    respond()
    render(<SecurityCenter projectId="project-1" />)
    expect(await screen.findByText('Not scanned yet')).toBeTruthy()
    expect(screen.getByText('No findings recorded. Run a supported scan to produce evidence.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Static analysis' }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: 'API security' }).hasAttribute('disabled')).toBe(true)
    fireEvent.change(screen.getByLabelText('Project directory path'), { target: { value: 'C:\\work\\project' } })
    expect(screen.getByRole('button', { name: 'Register' }).hasAttribute('disabled')).toBe(true)
    fireEvent.click(screen.getByLabelText(/I authorize bounded source/))
    expect(screen.getByRole('button', { name: 'Register' }).hasAttribute('disabled')).toBe(false)
    expect(screen.getByLabelText('Finding counts').textContent).toContain('0')
  })

  it('renders API evidence, filters findings, and opens the evidence inspector', async () => {
    respond({ findings: [finding, { ...finding, id: 'finding-2', title: 'Low confidence type mismatch', severity: 'low', status: 'suspected', category: 'input-validation' }] })
    render(<SecurityCenter projectId="project-1" />)
    const row = await screen.findByRole('button', { name: /Synthetic document ownership mismatch/ })
    fireEvent.click(row)
    expect(screen.getByText('Observed HTTP 200 and a response owner of bob.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Filter severity'), { target: { value: 'high' } })
    expect(screen.getAllByText('Synthetic document ownership mismatch')).toHaveLength(2)
    expect(screen.queryByText('Low confidence type mismatch')).toBeNull()
    expect(screen.getByText('Enforce document ownership before returning the record.')).toBeTruthy()
  })

  it('shows blocked scanner details and execution errors from a real scan record', async () => {
    respond({ scans: [blockedScan] })
    render(<SecurityCenter projectId="project-1" />)
    fireEvent.click(await screen.findByRole('button', { name: /Dependency audit.*Dependency analysis was blocked/ }))
    await waitFor(() => expect(screen.getAllByText('Blocked').length).toBeGreaterThan(0))
    expect(screen.getByText('pip-audit is not installed.')).toBeTruthy()
  })

  it('renders backend errors without inventing findings', async () => {
    vi.mocked(api.scanSource).mockRejectedValue(new Error('Security API unavailable'))
    vi.mocked(api.securityScans).mockResolvedValue([])
    vi.mocked(api.securityFindings).mockResolvedValue([])
    vi.mocked(api.targets).mockResolvedValue([])
    render(<SecurityCenter projectId="project-1" />)
    expect((await screen.findByRole('alert')).textContent).toContain('Security API unavailable')
    expect(screen.queryByText(/critical findings/i)).toBeNull()
  })

  it('clearly reports GitHub unavailable when no App credentials are configured', async () => {
    respond()
    render(<SecurityCenter projectId="project-1" />)
    expect(await screen.findByText('GitHub App integration is not configured on the backend.')).toBeTruthy()
    expect(screen.queryByRole('link', { name: /Connect GitHub/ })).toBeNull()
  })

  it('launches source analysis against a selected immutable GitHub snapshot', async () => {
    respond()
    vi.mocked(api.githubStatus).mockResolvedValue({ configured: true, connected: true, installations: [{ id: 'connection', installation_id: 42, login: 'octo', type: 'User' }], login: 'octo', account: 'octo', app_slug: 'failproof', read_only: true, permissions: ['contents:read', 'metadata:read'], message: null })
    vi.mocked(api.githubRepositories).mockResolvedValue([])
    vi.mocked(api.githubImports).mockResolvedValue([{ id: 'import-12345678-1234-1234-1234-123456789012', project_id: 'project-1', connection_id: 'connection', github_repository_id: 7, owner: 'octo', name: 'demo', full_name: 'octo/demo', html_url: 'https://github.com/octo/demo', default_branch: 'main', selected_branch: 'main', commit_sha: 'abcdef1234567890abcdef1234567890abcdef12', status: 'completed', workspace_relpath: 'snapshots/import', total_files: 8, indexed_file_count: 4, skipped_file_count: 4, imported_bytes: 2500, supported_scan_types: ['static'], error_detail: null, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z', imported_at: '2026-10-25T00:00:00Z' }])
    vi.mocked(api.startSecurityScan).mockResolvedValue({ ...blockedScan, id: 'github-scan', scan_type: 'static', status: 'queued', configuration: { source_kind: 'github' }, summary: 'Scan queued.' })
    render(<SecurityCenter projectId="project-1" />)
    expect(await screen.findByText('octo/demo')).toBeTruthy()
    expect(await screen.findByText(/abcdef123456/)).toBeTruthy()
    const scan = await screen.findByRole('button', { name: 'Static analysis' })
    expect(scan.hasAttribute('disabled')).toBe(false)
    fireEvent.click(scan)
    await waitFor(() => expect(api.startSecurityScan).toHaveBeenCalledWith('project-1', 'static', false, { source_kind: 'github', github_repository_id: 'import-12345678-1234-1234-1234-123456789012' }))
  })
})
