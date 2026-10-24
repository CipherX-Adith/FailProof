import type { AIStatus, ApiEndpoint, ApiTarget, GeneratedTest, GitHubBranch, GitHubImport, GitHubRepo, GitHubStatus, Project, ScanSource, ScanType, SecurityFinding, SecurityInvestigation, SecurityPatchProposal, SecurityScan, SecurityTestProposal, TestResult, TestRun } from '../types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, credentials: 'include', headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail || `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  projects: () => request<Project[]>('/api/projects'),
  createProject: (payload: { name: string; description: string; repository_url?: string }) => request<Project>('/api/projects', { method: 'POST', body: JSON.stringify(payload) }),
  targets: (projectId: string) => request<ApiTarget[]>(`/api/projects/${projectId}/targets`),
  registerDemo: (projectId: string, name: string, approveNonSafe: boolean) => request<ApiTarget>(`/api/projects/${projectId}/targets`, { method: 'POST', body: JSON.stringify({ name, base_url: 'http://127.0.0.1:8765', authorized: true, approve_non_safe_methods: approveNonSafe }) }),
  endpoints: (targetId: string, q = '', method = '') => request<ApiEndpoint[]>(`/api/targets/${targetId}/endpoints?q=${encodeURIComponent(q)}&method=${encodeURIComponent(method)}`),
  tests: (targetId: string) => request<GeneratedTest[]>(`/api/targets/${targetId}/tests`),
  endpointTests: (endpointId: string) => request<GeneratedTest[]>(`/api/endpoints/${endpointId}/tests`),
  generateTests: (targetId: string) => request<GeneratedTest[]>(`/api/targets/${targetId}/tests/generate`, { method: 'POST' }),
  runs: (targetId: string) => request<TestRun[]>(`/api/targets/${targetId}/runs`),
  runTests: (targetId: string, testIds: string[], approveNonSafe: boolean) => request<TestRun>(`/api/targets/${targetId}/runs`, { method: 'POST', body: JSON.stringify({ test_ids: testIds, approve_non_safe: approveNonSafe }) }),
  run: (runId: string) => request<TestRun>(`/api/runs/${runId}`),
  scanSource: (projectId: string) => request<ScanSource>(`/api/projects/${projectId}/security/source`),
  registerScanSource: (projectId: string, sourcePath: string) => request<ScanSource>(`/api/projects/${projectId}/security/source`, { method: 'PUT', body: JSON.stringify({ source_path: sourcePath, authorized: true }) }),
  securityScans: (projectId: string) => request<SecurityScan[]>(`/api/projects/${projectId}/security/scans`),
  startSecurityScan: (projectId: string, scanType: ScanType, approveStateChanges: boolean, source?: { source_kind: 'local' | 'github'; github_repository_id?: string }) => request<SecurityScan>(`/api/projects/${projectId}/security/scans`, { method: 'POST', body: JSON.stringify({ scan_type: scanType, approve_state_changes: approveStateChanges, ...source }) }),
  githubStatus: () => request<GitHubStatus>('/api/github/status'),
  githubRepositories: (connectionId: string) => request<GitHubRepo[]>(`/api/github/repositories?connection_id=${encodeURIComponent(connectionId)}`),
  githubBranches: (repo: GitHubRepo, connectionId: string) => request<GitHubBranch[]>(`/api/github/repositories/${repo.id}/branches?owner=${encodeURIComponent(repo.owner)}&name=${encodeURIComponent(repo.name)}&connection_id=${encodeURIComponent(connectionId)}`),
  githubImports: (projectId: string) => request<GitHubImport[]>(`/api/github/projects/${projectId}/imports`),
  githubImport: (projectId: string, repositoryId: number, branch: string, connectionId: string) => request<GitHubImport>(`/api/github/projects/${projectId}/imports`, { method: 'POST', body: JSON.stringify({ repository_id: repositoryId, branch, connection_id: connectionId }) }),
  retryGitHubImport: (projectId: string, importId: string, connectionId: string) => request<GitHubImport>(`/api/github/projects/${projectId}/imports/${importId}/retry?connection_id=${encodeURIComponent(connectionId)}`, { method: 'POST' }),
  removeGitHubImport: (projectId: string, importId: string, connectionId: string) => request<void>(`/api/github/projects/${projectId}/imports/${importId}?connection_id=${encodeURIComponent(connectionId)}`, { method: 'DELETE' }),
  securityScan: (scanId: string) => request<SecurityScan>(`/api/security/scans/${scanId}`),
  securityFindings: (projectId: string, filters: { severity?: string; category?: string; status?: string; source?: string; q?: string } = {}) => {
    const params = new URLSearchParams(Object.entries(filters).filter((entry): entry is [string, string] => Boolean(entry[1])))
    return request<SecurityFinding[]>(`/api/projects/${projectId}/security/findings${params.size ? `?${params}` : ''}`)
  },
  securityFinding: (findingId: string) => request<SecurityFinding>(`/api/security/findings/${findingId}`),
  aiStatus: () => request<AIStatus>('/api/ai/status'),
  investigations: (findingId: string) => request<SecurityInvestigation[]>(`/api/security/findings/${findingId}/investigations`),
  investigate: (findingId: string) => request<SecurityInvestigation>(`/api/security/findings/${findingId}/investigations`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } }),
  investigation: (investigationId: string) => request<SecurityInvestigation>(`/api/security/investigations/${investigationId}`),
  testProposals: (investigationId: string) => request<SecurityTestProposal[]>(`/api/security/investigations/${investigationId}/test-proposals`),
  generateTestProposals: (investigationId: string) => request<SecurityTestProposal[]>(`/api/security/investigations/${investigationId}/test-proposals`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } }),
  testDecision: (proposalId: string, decision: 'approve' | 'reject') => request<SecurityTestProposal>(`/api/security/test-proposals/${proposalId}/${decision}`, { method: 'POST', body: JSON.stringify({ note: '' }) }),
  executeTestProposal: (proposalId: string, approveStateChanges: boolean) => request<TestResult>(`/api/security/test-proposals/${proposalId}/execute`, { method: 'POST', body: JSON.stringify({ approve_state_changes: approveStateChanges }) }),
  patchProposals: (findingId: string) => request<SecurityPatchProposal[]>(`/api/security/findings/${findingId}/patch-proposals`),
  generatePatchProposal: (investigationId: string) => request<SecurityPatchProposal>(`/api/security/investigations/${investigationId}/patch-proposals`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } }),
  patchDecision: (proposalId: string, decision: 'approve' | 'reject') => request<SecurityPatchProposal>(`/api/security/patch-proposals/${proposalId}/${decision}`, { method: 'POST', body: JSON.stringify({ note: '' }) }),
  uploadSpec: async (targetId: string, file: File) => {
    const response = await fetch(`/api/targets/${targetId}/specifications?filename=${encodeURIComponent(file.name)}`, { method: 'POST', headers: { 'Content-Type': file.name.toLowerCase().endsWith('.json') ? 'application/json' : 'application/yaml' }, body: file })
    if (!response.ok) {
      const body = await response.json().catch(() => null)
      throw new Error(body?.detail || `Request failed (${response.status})`)
    }
    return response.json() as Promise<{ id: string; title: string; openapi_version: string; sha256: string }>
  },
}
