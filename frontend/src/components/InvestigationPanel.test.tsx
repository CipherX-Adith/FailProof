// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import InvestigationPanel from './InvestigationPanel'
import { api } from '../lib/api'
import type { SecurityFinding, SecurityInvestigation, SecurityPatchProposal, SecurityTestProposal } from '../types'

vi.mock('../lib/api', () => ({ api: {
  aiStatus: vi.fn(), investigations: vi.fn(), patchProposals: vi.fn(), testProposals: vi.fn(), investigate: vi.fn(), generateTestProposals: vi.fn(), testDecision: vi.fn(), executeTestProposal: vi.fn(), generatePatchProposal: vi.fn(), patchDecision: vi.fn(), run: vi.fn(),
} }))

afterEach(() => { cleanup(); vi.clearAllMocks() })

const finding: SecurityFinding = { id: 'finding-1', project_id: 'project-1', title: 'Shell execution pattern', description: 'A scanner reported shell execution.', category: 'static-analysis', severity: 'high', confidence: 'high', status: 'suspected', source: 'bandit', scan_type: 'static', scanner: 'Bandit', rule_id: 'B602', affected_resource: 'src/app.py', cwe_id: 'CWE-78', cve_id: null, remediation: 'Review source handling.', references: [], first_detected_at: '2026-10-25T00:00:00Z', last_observed_at: '2026-10-25T00:00:00Z', last_scan_id: 'scan-1', evidence: [] }
const investigation: SecurityInvestigation = { id: 'investigation-1', project_id: 'project-1', finding_id: 'finding-1', provider: 'openai-compatible', model: 'configured-model', status: 'completed', evidence_references: ['evidence-1'], verified_code_references: [{ path: 'src/app.py', line: 7, evidence_id: 'evidence-1' }], summary: 'A likely unsafe shell invocation.', likely_root_cause: 'Untrusted data may reach the shell.', confidence: 'medium', confidence_explanation: 'Only a static finding is available.', supporting_observations: [{ text: 'The finding identifies shell=True.', evidence_ids: ['evidence-1'] }], contradictory_or_missing_evidence: ['No runtime data flow was observed.'], alternative_explanations: ['The input may be constrained.'], preconditions: ['An untrusted value reaches the call.'], potential_impact: 'Possible command execution under stated conditions.', limitations: ['Hypothesis, not proof.'], validation_steps: ['Trace input data flow.'], remediation_approach: 'Use argument-vector execution.', unverified_references: [], error_detail: null, created_at: '2026-10-25T00:00:00Z', completed_at: '2026-10-25T00:00:05Z' }
const patch: SecurityPatchProposal = { id: 'patch-1', project_id: 'project-1', finding_id: 'finding-1', investigation_id: 'investigation-1', diff: '--- a/src/app.py\n+++ b/src/app.py\n@@ -7 +7 @@\n-old()\n+new()\n', rationale: 'Avoid shell parsing.', files_changed: ['src/app.py'], evidence_references: ['evidence-1'], applicability: 'applicable', status: 'awaiting_approval', decision_note: null, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z' }
const testProposal: SecurityTestProposal = { id: 'test-1', project_id: 'project-1', finding_id: 'finding-1', investigation_id: 'investigation-1', endpoint_id: null, execution_mode: 'manual', title: 'Trace untrusted argument', purpose: 'Check input provenance.', preconditions: [], parameters: {}, request_body: null, expected_statuses: ['200'], expected_behavior: 'No untrusted shell expansion occurs.', assertions: [], evidence_references: ['evidence-1'], state_changing: false, safety_classification: 'manual-review-only', status: 'proposed', execution_status: null, test_run_id: null, test_result_id: null, decision_note: null, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z' }

function setup({ available = false, runs = [], proposals = [], patches = [] }: { available?: boolean; runs?: SecurityInvestigation[]; proposals?: SecurityTestProposal[]; patches?: SecurityPatchProposal[] } = {}) {
  vi.mocked(api.aiStatus).mockResolvedValue({ available, provider: available ? 'openai-compatible' : null, model: available ? 'configured-model' : null, message: available ? null : 'AI investigation unavailable: configure a provider.' })
  vi.mocked(api.investigations).mockResolvedValue(runs)
  vi.mocked(api.testProposals).mockResolvedValue(proposals)
  vi.mocked(api.patchProposals).mockResolvedValue(patches)
}

describe('AI investigation panel', () => {
  it('shows an explicit provider unavailable state while keeping deterministic finding context visible', async () => {
    setup()
    render(<InvestigationPanel finding={finding} approveStateChanges={false}/>)
    expect(await screen.findByText('AI investigation unavailable: configure a provider.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Investigate finding' }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(/Scanner findings, evidence, and deterministic checks remain available/)).toBeTruthy()
  })

  it('labels AI output as hypotheses, shows only verified source references, and exposes the review diff', async () => {
    setup({ available: true, runs: [investigation], patches: [patch], proposals: [testProposal] })
    render(<InvestigationPanel finding={finding} approveStateChanges={false}/>)
    expect(await screen.findByText('A likely unsafe shell invocation.')).toBeTruthy()
    expect(screen.getByText('AI interpretation:')).toBeTruthy()
    expect(screen.getByText('Verified source reference:')).toBeTruthy()
    expect(screen.getByText('No runtime data flow was observed.')).toBeTruthy()
    fireEvent.click(screen.getByText('Review unified diff'))
    expect(screen.getByText(/-old()/)).toBeTruthy()
    expect(screen.getByText('Patch format validated')).toBeTruthy()
    expect(screen.getByText('Patch applicability checked')).toBeTruthy()
    expect(screen.getByText('Regression verification completed')).toBeTruthy()
    expect(screen.getByText('Fix verified')).toBeTruthy()
    expect(screen.getByText(/Patch approval and application require isolated execution and baseline preservation/)).toBeTruthy()
  })

  it('labels the deterministic demo provider as scripted mock output', async () => {
    const mockInvestigation = { ...investigation, provider: 'openai-compatible', model: 'failproof-demo-mock' }
    setup({ available: true, runs: [mockInvestigation] })
    vi.mocked(api.aiStatus).mockResolvedValue({ available: true, provider: 'openai-compatible', model: 'failproof-demo-mock', message: null })
    render(<InvestigationPanel finding={finding} approveStateChanges={false}/>)
    expect(await screen.findByText('Scripted mock results · failproof-demo-mock')).toBeTruthy()
    expect(screen.getByText(/not a response from a live hosted AI model/)).toBeTruthy()
  })

  it('labels a backend-validated real Gemini connection distinctly', async () => {
    setup()
    vi.mocked(api.aiStatus).mockResolvedValue({ available: true, configured: true, provider: 'gemini', model: 'gemini-3.8-flash', mode: 'real', message: null })
    render(<InvestigationPanel finding={finding} approveStateChanges={false}/>)
    expect(await screen.findByText('Gemini connected · gemini-3.8-flash')).toBeTruthy()
  })

  it('keeps investigation disabled when Gemini credentials are configured but the live model check fails', async () => {
    setup()
    vi.mocked(api.aiStatus).mockResolvedValue({ available: false, configured: true, provider: 'gemini', model: 'gemini-3.8-flash', mode: 'real', message: 'Gemini rejected the backend API key or model access.' })
    render(<InvestigationPanel finding={finding} approveStateChanges={false}/> )
    expect(await screen.findByText('Gemini rejected the backend API key or model access.')).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Investigate finding' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('persists a human test decision and does not execute a manual-only proposal', async () => {
    setup({ available: true, runs: [investigation], proposals: [testProposal] })
    vi.mocked(api.testDecision).mockResolvedValue({ ...testProposal, status: 'approved' })
    render(<InvestigationPanel finding={finding} approveStateChanges={false}/>)
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(screen.getByText('approved')).toBeTruthy())
    expect(screen.queryByRole('button', { name: 'Execute approved demo test' })).toBeNull()
  })
})
