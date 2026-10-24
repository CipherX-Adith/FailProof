import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('project API client', () => {
  it('lists projects from the backend', async () => {
    const projects = [{ id: 'p1', name: 'Payments', description: '', repository_url: null, created_at: '2026-10-24T00:00:00Z' }]
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => projects })
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.projects()).resolves.toEqual(projects)
    expect(fetchMock).toHaveBeenCalledWith('/api/projects', expect.objectContaining({ headers: { 'Content-Type': 'application/json' } }))
  })

  it('posts project input and surfaces backend errors', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ id: 'p2' }) })
      .mockResolvedValueOnce({ ok: false, status: 422, json: async () => ({ detail: 'Invalid project name' }) })
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.createProject({ name: 'Orders', description: '' })).resolves.toEqual({ id: 'p2' })
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ name: 'Orders', description: '' }) })
    await expect(api.projects()).rejects.toThrow('Invalid project name')
  })
})
