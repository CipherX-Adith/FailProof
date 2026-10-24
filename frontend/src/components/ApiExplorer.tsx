import { useEffect, useMemo, useState } from 'react'
import { AlertCircle, ArrowRight, Check, ChevronRight, Clock3, FileUp, FlaskConical, LockKeyhole, Play, Plus, RefreshCw, Search, ShieldAlert } from 'lucide-react'
import { api } from '../lib/api'
import type { ApiEndpoint, ApiTarget, GeneratedTest, Project, TestRun } from '../types'
import './api-explorer.css'

const methodColors: Record<string, string> = { GET: 'get', POST: 'post', PUT: 'put', PATCH: 'patch', DELETE: 'delete' }

export default function ApiExplorer({ project, onEvents, onRunning }: { project: Project; onEvents: (events: string[]) => void; onRunning: (running: boolean) => void }) {
  const [targets, setTargets] = useState<ApiTarget[]>([])
  const [target, setTarget] = useState<ApiTarget | null>(null)
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([])
  const [tests, setTests] = useState<GeneratedTest[]>([])
  const [runs, setRuns] = useState<TestRun[]>([])
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null)
  const [selectedRun, setSelectedRun] = useState<TestRun | null>(null)
  const [query, setQuery] = useState('')
  const [method, setMethod] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [allowNonSafe, setAllowNonSafe] = useState(false)
  const [targetName, setTargetName] = useState('Local demo API')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')

  const refresh = async (targetId: string) => {
    const [endpointRows, testRows, runRows] = await Promise.all([api.endpoints(targetId), api.tests(targetId), api.runs(targetId)])
    setEndpoints(endpointRows); setTests(testRows); setRuns(runRows)
    setSelectedEndpoint(current => endpointRows.find(row => row.id === current?.id) || endpointRows[0] || null)
    if (runRows[0]) {
      const latest = await api.run(runRows[0].id)
      setSelectedRun(latest)
      onEvents([`Historical run ${latest.id} · ${latest.result_count} persisted results`, ...latest.results.map(row => `${row.state.toUpperCase()} · ${row.method} ${row.endpoint_path} · ${row.actual_status ?? 'no response'}${row.duration_ms === null ? '' : ` · ${row.duration_ms} ms`}`)])
    }
  }
  useEffect(() => {
    let active = true
    api.targets(project.id).then(rows => { if (active) { setTargets(rows); const selected = rows.find(t => t.id === target?.id) || rows[0] || null; setTarget(selected); if (selected) void refresh(selected.id).catch(e => active && setError(e.message)) } }).catch(e => active && setError(e.message))
    return () => { active = false }
    // Refresh when changing projects; target selection is handled by its own control.
  }, [project.id])
  useEffect(() => { if (!target) return; api.endpoints(target.id, query, method).then(setEndpoints).catch(e => setError(e.message)) }, [target?.id, query, method])

  const selectedTests = useMemo(() => tests.filter(test => test.endpoint_id === selectedEndpoint?.id), [tests, selectedEndpoint])
  const safeTests = selectedTests.filter(test => !test.requires_approval)
  const gatedTests = selectedTests.filter(test => test.requires_approval)

  async function register() {
    setBusy(true); setError(''); setNote('')
    try {
      const created = await api.registerDemo(project.id, targetName.trim(), allowNonSafe)
      setTargets(current => [created, ...current]); setTarget(created); setAuthorized(false)
      setNote('Demo target registered. Import its OpenAPI document to discover endpoints.')
      onEvents([`Target registered: ${created.name} (${created.base_url})`])
    } catch (e) { setError(e instanceof Error ? e.message : 'Target registration failed') }
    finally { setBusy(false) }
  }

  async function importSpec() {
    if (!target || !file) return
    setBusy(true); setError(''); setNote('')
    try {
      const result = await api.uploadSpec(target.id, file)
      const importedEndpoints = await api.endpoints(target.id)
      await refresh(target.id)
      setNote(`Imported ${result.title} · OpenAPI ${result.openapi_version} · ${importedEndpoints.length} operations discovered`)
      onEvents([`Specification imported: ${result.title} · SHA-256 ${result.sha256}`])
    } catch (e) { setError(e instanceof Error ? e.message : 'Specification import failed') }
    finally { setBusy(false) }
  }

  async function generate() {
    if (!target) return
    setBusy(true); setError(''); setNote('')
    try { const generated = await api.generateTests(target.id); setTests(generated); setNote(`${generated.length} structured tests generated from the imported contract and explicit demo rules.`); onEvents([`Generated ${generated.length} reviewable tests from the imported OpenAPI document.`]) }
    catch (e) { setError(e instanceof Error ? e.message : 'Test generation failed') }
    finally { setBusy(false) }
  }

  async function runSelected() {
    if (!target || !selectedTests.length) return
    setBusy(true); setError(''); setNote('')
    onEvents([`Execution started · ${selectedTests.length} tests selected for ${selectedEndpoint?.method} ${selectedEndpoint?.path}`])
    onRunning(true)
    try {
      const result = await api.runTests(target.id, selectedTests.map(test => test.id), authorized && allowNonSafe)
      setSelectedRun(result); setRuns(current => [result, ...current]);
      onEvents([`Run ${result.id} completed`, ...result.results.map(row => `${row.state.toUpperCase()} · ${row.method} ${row.endpoint_path} · ${row.actual_status ?? 'no response'}${row.duration_ms === null ? '' : ` · ${row.duration_ms} ms`}${row.error_detail ? ` · ${row.error_detail}` : ''}`)])
    } catch (e) { const message = e instanceof Error ? e.message : 'Test run failed'; setError(message); onEvents([`Execution error · ${message}`]) }
    finally { setBusy(false); onRunning(false) }
  }

  async function selectHistoricalRun(run: TestRun) {
    setBusy(true)
    try { const detail = await api.run(run.id); setSelectedRun(detail) }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not load run') }
    finally { setBusy(false) }
  }

  return <div className="api-explorer">
    <div className="api-work-title"><div><div className="eyebrow"><span className="eyebrow-mark"/>API TESTING · LOCAL DEMO ONLY</div><h2>API Explorer</h2><p>Import a contract, review generated tests, then execute them against the controlled loopback demo.</p></div><span className="local-badge"><LockKeyhole size={13}/>Restricted target</span></div>
    {error && <div className="api-alert"><AlertCircle size={15}/><span>{error}</span><button onClick={() => setError('')}>Dismiss</button></div>}{note && <div className="api-note"><Check size={14}/>{note}</div>}
    {!targets.length ? <div className="setup-panel"><div className="setup-head"><div className="setup-icon"><ShieldAlert size={18}/></div><div><h3>Register the bundled demo API</h3><p>Requests are restricted by the backend to <code>127.0.0.1:8765</code>. Remote hosts are rejected.</p></div></div><label className="field-label">Display name<input value={targetName} maxLength={100} onChange={e => setTargetName(e.target.value)} /></label><label className="consent-row"><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)}/><span>I authorize this local synthetic demo API for testing.</span></label><label className="consent-row"><input type="checkbox" checked={allowNonSafe} onChange={e => setAllowNonSafe(e.target.checked)}/><span>Allow state-changing demo methods after explicit run approval.</span></label><button className="button primary" disabled={!authorized || !targetName.trim() || busy} onClick={() => void register()}><Plus size={15}/>{busy ? 'Registering…' : 'Register local target'}</button></div> : <>
      <div className="target-strip"><div className="target-state"><span className={`target-state-dot ${target?.status === 'ready' ? 'ready' : ''}`}/><div><strong>{target?.name}</strong><small>{target?.base_url} · {target?.status === 'ready' ? 'Specification ready' : 'Awaiting specification'}</small></div></div><button className="text-button" onClick={() => { setTarget(null); setTargets([]); setEndpoints([]); setTests([]) }}>Register another demo</button></div>
      {target?.status !== 'ready' ? <div className="setup-panel import-panel"><div className="setup-head"><div className="setup-icon"><FileUp size={18}/></div><div><h3>Import an OpenAPI document</h3><p>Upload the bundled <code>demo_api/openapi.yaml</code> or another reviewed specification. Max 1 MB.</p></div></div><div className="upload-row"><input type="file" accept=".json,.yaml,.yml,application/json,application/yaml" onChange={e => setFile(e.target.files?.[0] || null)}/><button className="button primary" disabled={!file || busy} onClick={() => void importSpec()}><FileUp size={14}/>{busy ? 'Importing…' : 'Import specification'}</button></div></div> : <>
        <div className="explorer-toolbar"><div className="filter-search"><Search size={14}/><input placeholder="Filter endpoint paths" value={query} onChange={e => setQuery(e.target.value)}/></div><select value={method} onChange={e => setMethod(e.target.value)}><option value="">All methods</option>{['GET','POST','PUT','PATCH','DELETE'].map(m => <option key={m}>{m}</option>)}</select><span className="endpoint-count">{endpoints.length} endpoints</span><button className="button secondary" disabled={busy} onClick={() => void refresh(target!.id)}><RefreshCw size={13}/>Refresh</button></div>
        <div className="api-work-grid"><section className="endpoint-list"><div className="panel-caption">DISCOVERED ENDPOINTS <span>{endpoints.length}</span></div>{endpoints.length ? endpoints.map(endpoint => <button key={endpoint.id} className={`endpoint-row ${selectedEndpoint?.id === endpoint.id ? 'chosen' : ''}`} onClick={() => { setSelectedEndpoint(endpoint); setSelectedRun(null) }}><span className={`method-pill ${methodColors[endpoint.method] || 'other'}`}>{endpoint.method}</span><span className="endpoint-path">{endpoint.path}<small>{endpoint.summary || endpoint.operation_id}</small></span><ChevronRight size={14}/></button>) : <div className="subtle-empty">No endpoints match this filter.</div>}</section>
          <section className="endpoint-detail">{selectedEndpoint ? <><div className="detail-top"><div><div className="operation-line"><span className={`method-pill ${methodColors[selectedEndpoint.method] || 'other'}`}>{selectedEndpoint.method}</span><code>{selectedEndpoint.path}</code></div><h3>{selectedEndpoint.summary || selectedEndpoint.operation_id || 'Untitled operation'}</h3><small>{selectedEndpoint.operation_id || 'No operation ID in specification'}</small></div><button className="button primary" disabled={!selectedTests.length || busy} onClick={() => void runSelected()}><Play size={14}/>Run {selectedTests.length || 'selected'} tests</button></div>
            <div className="detail-tabs"><span>Contract</span><button onClick={() => document.getElementById('cases')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })}>Test cases ({selectedTests.length}) <ArrowRight size={12}/></button><button onClick={() => document.getElementById('history')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })}>Run history ({runs.length}) <ArrowRight size={12}/></button></div>
            <div className="contract-section"><h4>Parameters</h4>{selectedEndpoint.parameters.length ? <div className="contract-table">{selectedEndpoint.parameters.map(p => <div className="contract-row" key={`${p.in}.${p.name}`}><code>{p.name}</code><span>{p.in}</span><span>{String(p.schema?.type || 'any')}{p.required ? ' · required' : ''}</span><small>{p.description}</small></div>)}</div> : <p className="muted-copy">No parameters declared.</p>}</div>
            {selectedEndpoint.request_schema && <div className="contract-section"><h4>Request body {selectedEndpoint.required_fields.length > 0 && <small>required: {selectedEndpoint.required_fields.join(', ')}</small>}</h4><pre>{JSON.stringify(selectedEndpoint.request_schema, null, 2)}</pre></div>}
            <div className="contract-section"><h4>Expected responses</h4><div className="response-list">{Object.entries(selectedEndpoint.responses).map(([code, response]) => <div className="response-line" key={code}><span className={`response-code ${code.startsWith('2') ? 'ok' : code.startsWith('4') ? 'client' : ''}`}>{code}</span><span>{response.description || 'No description'}</span><small>{response.content_types.join(', ')}</small>{Object.keys(response.schemas || {}).length > 0 && <pre>{JSON.stringify(response.schemas, null, 2)}</pre>}</div>)}</div></div>
            <section id="cases" className="contract-section"><div className="section-row"><h4>Reviewable test cases <span>{selectedTests.length}</span></h4><button className="button secondary" disabled={busy} onClick={() => void generate()}><FlaskConical size={13}/>Generate tests</button></div>{selectedTests.length ? <><div className="test-case-list">{selectedTests.map(test => <div className="test-case" key={test.id}><div className="test-case-head"><span className={`case-category ${test.category}`}>{test.category}</span><strong>{test.name}</strong>{test.requires_approval && <span className="approval-tag"><LockKeyhole size={11}/>approval</span>}</div><p>{test.expected_behavior}</p><small>{test.rationale}</small></div>)}</div>{gatedTests.length > 0 && <label className="consent-row run-consent"><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} disabled={!allowNonSafe}/><span>Approve state-changing/repeated cases for this run ({gatedTests.length}); safe cases: {safeTests.length}.</span></label>}{selectedTests.some(t => t.requires_approval) && !authorized && <div className="approval-note"><LockKeyhole size={13}/>Approval cases will be recorded as Blocked until you authorize the local demo run.</div>}</> : <p className="muted-copy">Generate tests from this target's imported contract to review them here.</p>}</section>
            <section id="history" className="contract-section"><div className="section-row"><h4>Execution history <span>{runs.length}</span></h4></div>{selectedRun && <div className="run-detail"><div className="run-detail-head"><strong>{selectedRun.id === runs[0]?.id ? 'Latest execution' : 'Historical execution'}</strong><span>{selectedRun.status} · {new Date(selectedRun.started_at).toLocaleString()}</span></div>{selectedRun.results.map(result => <div className="result-row-wrap" key={result.id}><div className="result-line"><span className={`result-state ${result.state}`}>{result.state}</span><span>{result.method} {result.endpoint_path}</span><span>{result.actual_status ?? 'No response'}</span><span>{result.duration_ms === null ? '—' : `${result.duration_ms} ms`}</span></div>{result.error_detail && <small className="result-error">{result.error_detail}</small>}<details className="result-evidence"><summary>Sanitized evidence</summary><pre>{JSON.stringify(result.evidence, null, 2)}</pre></details></div>)}</div>}{runs.length ? <div className="history-list">{runs.map(run => <button key={run.id} onClick={() => void selectHistoricalRun(run)}><Clock3 size={13}/><span>{new Date(run.started_at).toLocaleString()}</span><small>{run.result_count} results</small><ArrowRight size={13}/></button>)}</div> : <p className="muted-copy">No test runs recorded for this target.</p>}</section>
          </> : <div className="subtle-empty">Select an endpoint to inspect its contract and tests.</div>}</section>
        </div>
      </>}
    </>}
  </div>
}
