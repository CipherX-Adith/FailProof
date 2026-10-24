import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertCircle, CheckCircle2, Clock3, FileSearch, LockKeyhole, Play, RefreshCw, ShieldAlert } from 'lucide-react'
import { api } from '../lib/api'
import type { ScanSource, ScanType, SecurityFinding, SecurityScan } from '../types'
import InvestigationPanel from './InvestigationPanel'
import GitHubImportPanel from './GitHubImportPanel'
import type { GitHubImport } from '../types'
import './security-center.css'

const scanLabels: Record<ScanType, string> = { static: 'Static analysis', dependencies: 'Dependency audit', api_security: 'API security checks', business_logic: 'Business logic rules' }
const statusLabels: Record<string, string> = { queued: 'Queued', running: 'Running', completed: 'Completed', completed_with_errors: 'Completed with errors', failed: 'Failed', blocked: 'Blocked' }

type Props = { projectId: string }

export default function SecurityCenter({ projectId }: Props) {
  const [source, setSource] = useState<ScanSource | null>(null)
  const [githubImport, setGitHubImport] = useState<GitHubImport | null>(null)
  const [scanSourceMode, setScanSourceMode] = useState<'local' | 'github'>('local')
  const [sourcePath, setSourcePath] = useState('')
  const [authorizeSource, setAuthorizeSource] = useState(false)
  const [scans, setScans] = useState<SecurityScan[]>([])
  const [findings, setFindings] = useState<SecurityFinding[]>([])
  const [targetsReady, setTargetsReady] = useState(false)
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null)
  const [selectedScan, setSelectedScan] = useState<SecurityScan | null>(null)
  const [filters, setFilters] = useState({ q: '', severity: '', category: '', status: '', source: '' })
  const [approveStateChanges, setApproveStateChanges] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const handleGitHubSelect = useCallback((row: GitHubImport | null) => {
    setGitHubImport(row)
    if (row) setScanSourceMode('github')
  }, [])

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    setError('')
    try {
      const [sourceRow, scanRows, findingRows, targets] = await Promise.all([api.scanSource(projectId), api.securityScans(projectId), api.securityFindings(projectId), api.targets(projectId)])
      setSource(sourceRow); setScans(scanRows); setFindings(findingRows); setTargetsReady(targets.some(target => target.authorized && target.status === 'ready'))
      setSelectedFinding(current => current ? findingRows.find(finding => finding.id === current.id) || null : current)
      setSelectedScan(current => current ? scanRows.find(scan => scan.id === current.id) || null : current)
    } catch (value) { setError(value instanceof Error ? value.message : 'Security results could not be loaded.') }
    finally { if (!quiet) setLoading(false) }
  }, [projectId])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => {
    if (!scans.some(scan => scan.status === 'queued' || scan.status === 'running')) return
    const timer = window.setInterval(() => { void refresh(true) }, 1500)
    return () => window.clearInterval(timer)
  }, [scans, refresh])

  const filteredFindings = useMemo(() => findings.filter(finding => {
    const query = filters.q.trim().toLowerCase()
    return (!query || `${finding.title} ${finding.description} ${finding.affected_resource} ${finding.rule_id}`.toLowerCase().includes(query)) && (!filters.severity || finding.severity === filters.severity) && (!filters.category || finding.category === filters.category) && (!filters.status || finding.status === filters.status) && (!filters.source || finding.source === filters.source)
  }), [findings, filters])

  const severityCounts = useMemo(() => findings.reduce<Record<string, number>>((counts, finding) => { counts[finding.severity] = (counts[finding.severity] || 0) + 1; return counts }, {}), [findings])
  const statusCounts = useMemo(() => findings.reduce<Record<string, number>>((counts, finding) => { counts[finding.status] = (counts[finding.status] || 0) + 1; return counts }, {}), [findings])
  const categories = useMemo(() => [...new Set(findings.map(finding => finding.category))].sort(), [findings])
  const sources = useMemo(() => [...new Set(findings.map(finding => finding.source))].sort(), [findings])

  async function saveSource(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setNotice(''); setError('')
    try { const registered = await api.registerScanSource(projectId, sourcePath); setSource(registered); setSourcePath(''); setAuthorizeSource(false); setNotice(`Registered ${registered.source_name || 'source directory'} for this project.`) }
    catch (value) { setError(value instanceof Error ? value.message : 'Source registration failed.') }
    finally { setBusy(false) }
  }

  async function launch(scanType: ScanType) {
    setBusy(true); setError(''); setNotice('')
    try {
      const githubMode = scanSourceMode === 'github' && ['static', 'dependencies'].includes(scanType)
      const queued = await api.startSecurityScan(projectId, scanType, approveStateChanges, githubMode ? { source_kind: 'github', github_repository_id: githubImport?.id } : { source_kind: 'local' })
      setSelectedScan(queued); setNotice(`${scanLabels[scanType]} queued.`)
      await refresh(true)
    } catch (value) { setError(value instanceof Error ? value.message : 'Scan could not be started.') }
    finally { setBusy(false) }
  }

  return <section className="security-center" aria-label="Security Center">
    {error && <div className="security-alert error" role="alert"><AlertCircle size={15}/><span>{error}</span><button onClick={() => void refresh()}>Retry</button></div>}
    {notice && <div className="security-alert success" role="status"><CheckCircle2 size={15}/>{notice}<button aria-label="Dismiss notice" onClick={() => setNotice('')}>×</button></div>}

    <div className="security-overview">
      <div className="security-summary"><div className="security-section-label"><ShieldAlert size={15}/>SCAN OVERVIEW</div><h2>{scans.length ? 'Observed security activity' : 'Not scanned yet'}</h2><p>{scans.length ? `${scans.length} scan record${scans.length === 1 ? '' : 's'} for this project. Findings below come from scanner or test evidence.` : 'Run a supported scan to collect evidence. An empty state does not imply the project is clean.'}</p><button className="button secondary" onClick={() => void refresh()} disabled={loading}><RefreshCw size={14}/>Refresh results</button></div>
      <div className="security-metrics" aria-label="Finding counts">
        <div><strong>{severityCounts.critical || 0}</strong><span>Critical</span></div><div><strong>{severityCounts.high || 0}</strong><span>High</span></div><div><strong>{severityCounts.medium || 0}</strong><span>Medium</span></div><div><strong>{severityCounts.low || 0}</strong><span>Low</span></div>
        <p>Status counts · Confirmed {statusCounts.confirmed || 0} · Suspected {statusCounts.suspected || 0} · Resolved {statusCounts.resolved || 0}</p>
      </div>
    </div>

    <div className="security-controls">
      <GitHubImportPanel projectId={projectId} selectedId={githubImport?.id} onSelect={handleGitHubSelect}/>
      <section className="security-card source-card">
        <div className="security-card-title"><FileSearch size={15}/><h3>Registered source</h3><span className={`security-badge ${source?.authorized ? 'good' : 'muted'}`}>{source?.authorized ? 'Authorized' : 'Not configured'}</span></div>
        {source?.configured ? <p className="security-copy">Scanning <strong>{source.source_name}</strong>. The full path remains local to the backend.</p> : <p className="security-copy">No source directory is registered. The backend accepts only paths beneath its configured allowlist.</p>}
        <form className="source-form" onSubmit={saveSource}><label htmlFor="security-source-path">Project directory path</label><div><input id="security-source-path" value={sourcePath} onChange={event => setSourcePath(event.target.value)} placeholder="C:\\work\\my-project" maxLength={1000}/><button className="button secondary" disabled={busy || !sourcePath.trim() || !authorizeSource} type="submit">Register</button></div><label className="scan-approval"><input type="checkbox" checked={authorizeSource} onChange={event => setAuthorizeSource(event.target.checked)}/> I authorize bounded source and dependency analysis of this directory.</label><small>The backend accepts only directories beneath its configured allowlist. The full path stays local to the backend.</small></form>
      </section>
      <section className="security-card launch-card">
        <div className="security-card-title"><Play size={15}/><h3>Launch a scan</h3></div>
        {(source?.authorized || githubImport) && <label className="scan-source-select">Source for static and dependency scans<select value={scanSourceMode} onChange={event => setScanSourceMode(event.target.value as 'local' | 'github')}><option value="local" disabled={!source?.authorized}>Authorized local directory</option><option value="github" disabled={!githubImport}>Imported GitHub snapshot{githubImport ? ` · ${githubImport.full_name} @ ${githubImport.commit_sha.slice(0, 8)}` : ''}</option></select></label>}
        <div className="scan-buttons">
          <button className="button secondary" disabled={busy || (scanSourceMode === 'github' ? !githubImport?.supported_scan_types.includes('static') : !source?.authorized)} onClick={() => void launch('static')}>Static analysis</button>
          <button className="button secondary" disabled={busy || (scanSourceMode === 'github' ? !githubImport?.supported_scan_types.includes('dependencies') : !source?.authorized)} onClick={() => void launch('dependencies')}>Dependency audit</button>
          <button className="button secondary" disabled={busy || !targetsReady} onClick={() => void launch('api_security')}>API security</button>
          <button className="button secondary" disabled={busy || !targetsReady} onClick={() => void launch('business_logic')}>Business logic</button>
        </div>
        <label className="scan-approval"><input type="checkbox" checked={approveStateChanges} onChange={event => setApproveStateChanges(event.target.checked)}/> Approve synthetic state-changing checks for this run</label>
        <small>POST checks run only when this is checked and the demo target was separately registered to allow non-safe methods. All requests remain confined to the loopback demo API.</small>
        {!targetsReady && <div className="security-inline-note">Register the local demo API and import its OpenAPI contract to enable API and business checks.</div>}
      </section>
    </div>

    <div className="security-results-layout">
      <section className="security-card findings-card">
        <div className="security-card-title"><ShieldAlert size={15}/><h3>Findings</h3><span className="result-count">{filteredFindings.length} shown</span></div>
        <div className="finding-filters"><input aria-label="Search findings" value={filters.q} onChange={event => setFilters(current => ({ ...current, q: event.target.value }))} placeholder="Search title, resource, or rule"/><select aria-label="Filter severity" value={filters.severity} onChange={event => setFilters(current => ({ ...current, severity: event.target.value }))}><option value="">All severity</option>{['critical', 'high', 'medium', 'low', 'informational', 'unknown'].map(value => <option key={value}>{value}</option>)}</select><select aria-label="Filter category" value={filters.category} onChange={event => setFilters(current => ({ ...current, category: event.target.value }))}><option value="">All categories</option>{categories.map(value => <option key={value}>{value}</option>)}</select><select aria-label="Filter status" value={filters.status} onChange={event => setFilters(current => ({ ...current, status: event.target.value }))}><option value="">All statuses</option>{['confirmed', 'suspected', 'not_reproduced', 'verification_blocked', 'resolved'].map(value => <option key={value}>{value}</option>)}</select><select aria-label="Filter source" value={filters.source} onChange={event => setFilters(current => ({ ...current, source: event.target.value }))}><option value="">All sources</option>{sources.map(value => <option key={value}>{value}</option>)}</select></div>
        {loading ? <div className="security-empty">Loading findings…</div> : filteredFindings.length ? <div className="finding-list">{filteredFindings.map(finding => <button key={finding.id} className={`finding-row ${selectedFinding?.id === finding.id ? 'selected' : ''}`} onClick={() => setSelectedFinding(finding)}><span className={`severity-dot ${finding.severity}`}/><span className="finding-row-main"><strong>{finding.title}</strong><small>{finding.affected_resource || finding.source} · {finding.rule_id}</small></span><span className={`finding-status ${finding.status}`}>{finding.status.replace(/_/g, ' ')}</span></button>)}</div> : <div className="security-empty">{findings.length ? 'No findings match these filters.' : 'No findings recorded. Run a supported scan to produce evidence.'}</div>}
      </section>
      <aside className="security-card finding-inspector" aria-live="polite">
        {selectedFinding ? <><div className="security-card-title"><LockKeyhole size={15}/><h3>Finding detail</h3></div><span className={`finding-status large ${selectedFinding.status}`}>{selectedFinding.status.replace(/_/g, ' ')}</span><h4>{selectedFinding.title}</h4><div className="finding-meta"><span>{selectedFinding.severity}</span><span>{selectedFinding.confidence} confidence</span><span>{selectedFinding.source}</span></div><p>{selectedFinding.description}</p><dl><dt>Affected resource</dt><dd>{selectedFinding.affected_resource || 'Not provided by scanner'}</dd><dt>Rule / advisory</dt><dd>{selectedFinding.rule_id}</dd>{selectedFinding.cve_id && <><dt>CVE</dt><dd>{selectedFinding.cve_id}</dd></>}{selectedFinding.cwe_id && <><dt>CWE</dt><dd>{selectedFinding.cwe_id}</dd></>}</dl><h5>Remediation</h5><p>{selectedFinding.remediation}</p><h5>Evidence and reproduction</h5>{selectedFinding.evidence.length ? selectedFinding.evidence.map(evidence => <article className="evidence-record" key={evidence.id}><div><strong>{evidence.evidence_type}</strong><time>{new Date(evidence.created_at).toLocaleString()}</time></div>{evidence.relative_path && <code>{evidence.relative_path}{evidence.line_number ? `:${evidence.line_number}` : ''}</code>}{evidence.expected_result && <p><b>Expected:</b> {evidence.expected_result}</p>}{evidence.actual_result && <p><b>Observed:</b> {evidence.actual_result}</p>}<pre>{JSON.stringify(evidence.details, null, 2)}</pre><small>{evidence.redacted ? 'Sensitive values redacted' : 'No redaction reported'}{evidence.truncated ? ' · Evidence truncated' : ''}</small></article>) : <p>No evidence record is attached to this finding.</p>}{selectedFinding.references.map(reference => <a className="finding-reference" href={reference} key={reference} target="_blank" rel="noreferrer">Advisory reference ↗</a>)}</> : selectedScan ? <><div className="security-card-title"><Clock3 size={15}/><h3>Scan detail</h3></div><span className={`scan-status ${selectedScan.status}`}>{statusLabels[selectedScan.status] || selectedScan.status}</span><h4>{scanLabels[selectedScan.scan_type]}</h4><p>{selectedScan.summary}</p><dl><dt>Started</dt><dd>{new Date(selectedScan.started_at).toLocaleString()}</dd><dt>Finished</dt><dd>{selectedScan.completed_at ? new Date(selectedScan.completed_at).toLocaleString() : 'Still running'}</dd><dt>Findings</dt><dd>{selectedScan.finding_count}</dd>{selectedScan.configuration.source_kind === 'github' && <><dt>GitHub repository</dt><dd>{selectedScan.configuration.github_repository || 'Imported snapshot'}</dd><dt>Commit SHA</dt><dd><code>{selectedScan.configuration.github_commit_sha || 'Not recorded'}</code></dd></>}</dl><h5>Scanner availability</h5><pre>{JSON.stringify(selectedScan.scanner_availability, null, 2)}</pre>{selectedScan.errors.length > 0 && <><h5>Errors</h5><ul>{selectedScan.errors.map((item, index) => <li key={index}>{item}</li>)}</ul></>}{selectedScan.warnings.length > 0 && <><h5>Warnings</h5><ul>{selectedScan.warnings.map((item, index) => <li key={index}>{item}</li>)}</ul></>}</> : <div className="security-detail-empty"><ShieldAlert size={20}/><strong>Select a finding or scan</strong><span>Evidence and execution status appear here.</span></div>}
      </aside>
    </div>

    {selectedFinding && <InvestigationPanel key={selectedFinding.id} finding={selectedFinding} approveStateChanges={approveStateChanges}/>}

    <section className="security-card scan-history"><div className="security-card-title"><Clock3 size={15}/><h3>Scan history</h3><span className="result-count">{scans.length}</span></div>{loading ? <div className="security-empty">Loading scans…</div> : scans.length ? <div className="scan-history-list">{scans.map(scan => <button key={scan.id} onClick={() => setSelectedScan(scan)} className={selectedScan?.id === scan.id ? 'selected' : ''}><span className="scan-history-main"><strong>{scanLabels[scan.scan_type]}</strong><small>{new Date(scan.started_at).toLocaleString()} · {scan.summary}</small></span><span className={`scan-status ${scan.status}`}>{statusLabels[scan.status] || scan.status}</span></button>)}</div> : <div className="security-empty">No scans have run for this project.</div>}</section>
  </section>
}
