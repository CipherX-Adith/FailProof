import { useEffect, useState } from 'react'
import { AlertCircle, FlaskConical, GitPullRequest, Lightbulb, LoaderCircle, X } from 'lucide-react'
import { api } from '../lib/api'
import type { AIStatus, SecurityFinding, SecurityInvestigation, SecurityPatchProposal, SecurityTestProposal, TestResult } from '../types'

type Props = { finding: SecurityFinding; approveStateChanges: boolean }

async function loadExecutedResults(proposals: SecurityTestProposal[]) {
  const pairs = await Promise.all(proposals.filter(item => item.test_run_id).map(async item => {
    try {
      const run = await api.run(item.test_run_id!)
      const result = run.results.find(row => row.id === item.test_result_id)
      return result ? [item.id, result] as const : null
    } catch { return null }
  }))
  return Object.fromEntries(pairs.filter((pair): pair is readonly [string, TestResult] => pair !== null))
}

export default function InvestigationPanel({ finding, approveStateChanges }: Props) {
  const [ai, setAi] = useState<AIStatus | null>(null)
  const [history, setHistory] = useState<SecurityInvestigation[]>([])
  const [investigation, setInvestigation] = useState<SecurityInvestigation | null>(null)
  const [tests, setTests] = useState<SecurityTestProposal[]>([])
  const [patches, setPatches] = useState<SecurityPatchProposal[]>([])
  const [results, setResults] = useState<Record<string, TestResult>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const isMockResult = investigation?.model === 'failproof-demo-mock' || investigation?.provider === 'failproof-demo-mock'

  async function refreshFinding() {
    const [status, runs, proposals] = await Promise.all([api.aiStatus(), api.investigations(finding.id), api.patchProposals(finding.id)])
    setAi(status); setHistory(runs); setPatches(proposals)
    if (!investigation && runs.length) setInvestigation(runs[0])
    return runs
  }

  useEffect(() => {
    setAi(null); setHistory([]); setInvestigation(null); setTests([]); setPatches([]); setResults({}); setError('')
    void Promise.all([api.aiStatus(), api.investigations(finding.id), api.patchProposals(finding.id)]).then(([status, runs, proposals]) => {
      setAi(status); setHistory(runs); setPatches(proposals)
      if (runs.length) setInvestigation(runs[0])
    }).catch(value => setError(value instanceof Error ? value.message : 'Investigation history could not be loaded.'))
  }, [finding.id])

  useEffect(() => {
    if (!investigation) { setTests([]); return }
    void api.testProposals(investigation.id).then(async rows => { setTests(rows); setResults(await loadExecutedResults(rows)) }).catch(value => setError(value instanceof Error ? value.message : 'Test proposals could not be loaded.'))
  }, [investigation?.id])

  async function investigate() {
    setBusy(true); setError('')
    try {
      const current = await api.investigate(finding.id)
      setInvestigation(current)
      const runs = await api.investigations(finding.id); setHistory(runs)
      setTests(await api.testProposals(current.id))
      setPatches(await api.patchProposals(finding.id))
    } catch (value) { setError(value instanceof Error ? value.message : 'Investigation failed.') }
    finally { setBusy(false) }
  }

  async function createTests() {
    if (!investigation) return
    setBusy(true); setError('')
    try { setTests(await api.generateTestProposals(investigation.id)) }
    catch (value) { setError(value instanceof Error ? value.message : 'Test proposal generation failed.') }
    finally { setBusy(false) }
  }

  async function decideTest(proposal: SecurityTestProposal, decision: 'approve' | 'reject') {
    setBusy(true); setError('')
    try { const updated = await api.testDecision(proposal.id, decision); setTests(current => current.map(item => item.id === updated.id ? updated : item)) }
    catch (value) { setError(value instanceof Error ? value.message : 'Test decision could not be saved.') }
    finally { setBusy(false) }
  }

  async function executeTest(proposal: SecurityTestProposal) {
    setBusy(true); setError('')
    try { await api.executeTestProposal(proposal.id, approveStateChanges); const rows = await api.testProposals(proposal.investigation_id); setTests(rows); setResults(await loadExecutedResults(rows)) }
    catch (value) { setError(value instanceof Error ? value.message : 'Test execution was blocked.') }
    finally { setBusy(false) }
  }

  async function createPatch() {
    if (!investigation) return
    setBusy(true); setError('')
    try { await api.generatePatchProposal(investigation.id); setPatches(await api.patchProposals(finding.id)) }
    catch (value) { setError(value instanceof Error ? value.message : 'Patch proposal generation failed.') }
    finally { setBusy(false) }
  }

  async function decidePatch(proposal: SecurityPatchProposal, decision: 'approve' | 'reject') {
    setBusy(true); setError('')
    try { const updated = await api.patchDecision(proposal.id, decision); setPatches(current => current.map(item => item.id === updated.id ? updated : item)) }
    catch (value) { setError(value instanceof Error ? value.message : 'Patch decision could not be saved.') }
    finally { setBusy(false) }
  }

  return <section className="security-card investigation-panel" aria-label="AI investigation workflow">
    <header className="security-card-title"><Lightbulb size={16}/><h3>Evidence-grounded investigation</h3>{investigation && <span className={`scan-status ${investigation.status}`}>{investigation.status}</span>}</header>
    {error && <div className="security-alert error" role="alert"><AlertCircle size={14}/><span>{error}</span><button onClick={() => void refreshFinding().catch(value => setError(value.message))}>Retry</button></div>}
    <div className="investigation-toolbar"><div><strong>{ai?.available ? (ai.mode === 'mock' || ai.model === 'failproof-demo-mock' ? `Scripted mock results · ${ai.model}` : ai.provider === 'gemini' ? `Gemini connected · ${ai.model}` : `Provider ready · ${ai.provider} · ${ai.model}`) : ai?.message || 'Checking AI provider configuration…'}</strong><small>AI output remains a hypothesis; it does not change finding status or count as verification.</small></div><button className="button secondary" disabled={busy || !ai?.available} onClick={() => void investigate()}>{busy ? <LoaderCircle size={14} className="spin"/> : <Lightbulb size={14}/>}Investigate finding</button></div>
    {!ai?.available && <p className="ai-unavailable">AI investigation unavailable: configure a provider in the backend environment. Scanner findings, evidence, and deterministic checks remain available.</p>}
    {history.length > 0 && <div className="investigation-history"><strong>Previous investigations</strong>{history.map(item => <button key={item.id} className={investigation?.id === item.id ? 'selected' : ''} onClick={() => setInvestigation(item)}>{new Date(item.created_at).toLocaleString()} · {item.status}</button>)}</div>}
    {investigation && <>
      {investigation.status === 'completed' ? <div className="investigation-result">{isMockResult && <div className="ai-unavailable" role="note"><strong>Mock result:</strong> scripted local example from failproof-demo-mock; this is not a response from a live hosted AI model.</div>}
        <ol className="provenance-timeline"><li><span>Observed finding</span><small>{finding.title} · {finding.status}</small></li><li><span>AI hypothesis</span><small>{investigation.provider} · {investigation.model} · {investigation.confidence} confidence</small></li><li><span>Proposed validation</span><small>{tests.length} test proposal{tests.length === 1 ? '' : 's'}</small></li><li><span>Patch review</span><small>{patches.length} reviewable proposal{patches.length === 1 ? '' : 's'} · application not enabled</small></li></ol>
        <article className="investigation-section"><h4>Root-cause hypothesis</h4><p>{investigation.summary}</p><p>{investigation.likely_root_cause}</p><small>Confidence: {investigation.confidence}. {investigation.confidence_explanation}</small></article>
        <div className="investigation-columns"><article className="investigation-section"><h4>Evidence references and AI interpretations</h4>{investigation.evidence_references.length ? <ul>{investigation.evidence_references.map(id => <li key={id}><code>{id}</code></li>)}</ul> : <p>No evidence IDs were validated.</p>}{investigation.supporting_observations.map((item, index) => <p key={index}><strong>AI interpretation:</strong> {item.text} <small>Based on {item.evidence_ids.join(', ')}</small></p>)}{investigation.verified_code_references.map((item, index) => <p key={index}><strong>Verified source reference:</strong> <code>{item.path}:{item.line}</code> · evidence {item.evidence_id}</p>)}</article><article className="investigation-section"><h4>Missing evidence and alternatives</h4><ul>{investigation.contradictory_or_missing_evidence.map((item, index) => <li key={`m${index}`}>{item}</li>)}{investigation.alternative_explanations.map((item, index) => <li key={`a${index}`}>Alternative: {item}</li>)}</ul>{investigation.unverified_references.map((item, index) => <p className="unverified-ref" key={index}>Unverified: {item}</p>)}</article></div>
        <div className="investigation-columns"><article className="investigation-section"><h4>Impact and limitations</h4><p>{investigation.potential_impact}</p><ul>{investigation.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>{investigation.preconditions.length > 0 && <p><strong>Preconditions:</strong> {investigation.preconditions.join(' · ')}</p>}</article><article className="investigation-section"><h4>Validation and remediation</h4><ol>{investigation.validation_steps.map((item, index) => <li key={index}>{item}</li>)}</ol><p>{investigation.remediation_approach}</p></article></div>
        <div className="proposal-heading"><h4><FlaskConical size={15}/>Proposed reproduction tests</h4><button className="button secondary" disabled={busy || !ai?.available} onClick={() => void createTests()}>Generate proposals</button></div>
        {tests.length === 0 && <p className="ai-unavailable">No test proposal has been generated.</p>}
        {tests.map(test => <article className="proposal-card" key={test.id}><div className="proposal-title"><strong>{test.title}</strong><span className={`scan-status ${test.status}`}>{test.status}</span></div><p>{test.purpose}</p><p><strong>Expected:</strong> {test.expected_behavior}</p><p><strong>Mode:</strong> {test.execution_mode} · {test.safety_classification}{test.state_changing ? ' · state-changing' : ''}</p>{test.preconditions.length > 0 && <ul>{test.preconditions.map((item, index) => <li key={index}>{item}</li>)}</ul>}<div className="proposal-actions">{test.status === 'proposed' && <><button disabled={busy} onClick={() => void decideTest(test, 'approve')}>Approve</button><button disabled={busy} onClick={() => void decideTest(test, 'reject')}>Reject</button></>}{test.status === 'approved' && test.execution_mode === 'demo-api' && <button disabled={busy || (test.state_changing && !approveStateChanges)} onClick={() => void executeTest(test)}>Execute approved demo test</button>}</div>{test.state_changing && test.status === 'approved' && <small>Execution additionally requires the Security Center per-run checkbox and target-level non-safe approval.</small>}{results[test.id] && <div className="actual-result"><strong>Actual execution result: {results[test.id].state}</strong><span>HTTP {results[test.id].actual_status ?? 'not received'}</span><pre>{JSON.stringify(results[test.id].evidence, null, 2)}</pre></div>}{test.execution_status && <small>Recorded executor state: {test.execution_status}. This is not an AI expectation.</small>}<small>Evidence: {test.evidence_references.map(id => <code key={id}>{id} </code>)}</small></article>)}
        <div className="proposal-heading"><h4><GitPullRequest size={15}/>Reviewable patch proposals</h4><button className="button secondary" disabled={busy || !ai?.available || finding.scan_type !== 'static'} onClick={() => void createPatch()}>Propose patch</button></div>
        {finding.scan_type !== 'static' && <p className="ai-unavailable">Patch proposals currently support source-code findings with authorized, evidence-linked files.</p>}
        {patches.filter(item => item.investigation_id === investigation.id).map(patch => <article className="proposal-card patch-card" key={patch.id}><div className="proposal-title"><strong>{patch.files_changed.join(', ')}</strong><span className={`scan-status ${patch.status}`}>{patch.status}</span></div><p>{patch.rationale}</p><ol className="provenance-timeline patch-lifecycle"><li><span>Patch generated</span><small>Review diff below</small></li><li><span>Patch format validated</span><small>Passed server path, scope, evidence, and unified-diff checks</small></li><li><span>Patch applicability checked</span><small>{patch.applicability}{patch.applicability === 'stale' ? ' · source baseline changed or was not recorded' : patch.applicability === 'not-applicable' ? ' · Git rejected it for the authorized source state' : patch.applicability === 'check-unavailable' ? ' · Git check could not run' : ' · read-only check passed'}</small></li><li><span>Patch approved</span><small>{patch.status === 'approved' ? 'Legacy approval record' : patch.status === 'rejected' ? 'Rejected in review workflow' : patch.status === 'stale' ? 'Stale · regenerate against the current source' : 'Unavailable until safe isolated application exists'}</small></li><li><span>Patch applied</span><small>Not applied · operation unavailable</small></li><li><span>Regression verification completed</span><small>Not run · isolated execution unavailable</small></li><li><span>Fix verified</span><small>No verification record</small></li></ol><details><summary>Review unified diff</summary><pre>{patch.diff}</pre></details><div className="proposal-actions">{['draft', 'awaiting_approval'].includes(patch.status) && <button disabled={busy} onClick={() => void decidePatch(patch, 'reject')}><X size={13}/>Reject</button>}</div><small>Patch approval and application require isolated execution and baseline preservation, which are unavailable. No files have been changed.</small></article>)}
      </div> : investigation.status === 'unavailable' || investigation.status === 'failed' ? <div className="ai-unavailable" role="status">{investigation.error_detail || 'Investigation did not produce a result.'}</div> : <div className="ai-unavailable"><LoaderCircle size={14} className="spin"/>Investigation status: {investigation.status}</div>}
    </>}
  </section>
}
