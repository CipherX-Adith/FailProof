import type { ApiEndpoint, ApiTarget, GeneratedTest, Project, TestRun } from '../types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail || `Request failed (${response.status})`)
  }
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
  uploadSpec: async (targetId: string, file: File) => {
    const response = await fetch(`/api/targets/${targetId}/specifications?filename=${encodeURIComponent(file.name)}`, { method: 'POST', headers: { 'Content-Type': file.name.toLowerCase().endsWith('.json') ? 'application/json' : 'application/yaml' }, body: file })
    if (!response.ok) {
      const body = await response.json().catch(() => null)
      throw new Error(body?.detail || `Request failed (${response.status})`)
    }
    return response.json() as Promise<{ id: string; title: string; openapi_version: string; sha256: string }>
  },
}
