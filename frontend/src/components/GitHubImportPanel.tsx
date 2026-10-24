import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, GitBranch, Github, RefreshCw, Trash2 } from 'lucide-react'
import { api } from '../lib/api'
import type { GitHubBranch, GitHubImport, GitHubRepo, GitHubStatus } from '../types'

export default function GitHubImportPanel({ projectId, onSelect, selectedId }: { projectId: string; onSelect: (row: GitHubImport | null) => void; selectedId?: string }) {
  const [status, setStatus] = useState<GitHubStatus | null>(null)
  const [repos, setRepos] = useState<GitHubRepo[]>([])
  const [branches, setBranches] = useState<GitHubBranch[]>([])
  const [imports, setImports] = useState<GitHubImport[]>([])
  const [repoId, setRepoId] = useState('')
  const [connectionId, setConnectionId] = useState('')
  const [branch, setBranch] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    setError('')
    try {
      const github = await api.githubStatus(); setStatus(github)
      const imported = await api.githubImports(projectId).catch(() => [])
      setImports(imported)
      const isComplete = (row: GitHubImport) => row.status === 'completed' || row.status === 'completed_partial'
      const completed = imported.find(row => row.id === selectedId && isComplete(row)) || imported.find(isComplete) || null
      onSelect(completed)
      const selected = github.installations.find(item => item.id === connectionId) || github.installations[0]
      if (selected) { setConnectionId(selected.id); setRepos(await api.githubRepositories(selected.id)) }
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'GitHub integration status could not be loaded.') }
  }, [projectId, onSelect, selectedId, connectionId])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => {
    if (!imports.some(row => row.status === 'queued' || row.status === 'running')) return
    const timer = window.setInterval(() => { void refresh() }, 1800)
    return () => window.clearInterval(timer)
  }, [imports, refresh])

  const selectedRepo = repos.find(row => String(row.id) === repoId)
  async function chooseRepo(id: string) {
    setRepoId(id); setBranch(''); setBranches([]); setError('')
    const repo = repos.find(row => String(row.id) === id)
    if (!repo) return
    try { const rows = await api.githubBranches(repo, connectionId); setBranches(rows); setBranch(rows.find(row => row.name === repo.default_branch)?.name || rows[0]?.name || '') }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Branch list could not be loaded.') }
  }

  async function startImport() {
    if (!selectedRepo || !branch) return
    setBusy(true); setError('')
    try { await api.githubImport(projectId, selectedRepo.id, branch, connectionId); await refresh() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Repository import could not be started.') }
    finally { setBusy(false) }
  }

  async function retry(row: GitHubImport) {
    setBusy(true); setError('')
    try { await api.retryGitHubImport(projectId, row.id, row.connection_id); await refresh() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Import retry could not be started.') }
    finally { setBusy(false) }
  }

  async function remove(row: GitHubImport) {
    if (!window.confirm(`Remove the imported snapshot for ${row.full_name} at ${row.commit_sha.slice(0, 12)}?`)) return
    setBusy(true); setError('')
    try { await api.removeGitHubImport(projectId, row.id, row.connection_id); if (row.id === imports.find(x => x.status === 'completed')?.id) onSelect(null); await refresh() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Snapshot could not be removed.') }
    finally { setBusy(false) }
  }

  return <section className="security-card github-import-card" aria-label="GitHub repository import">
    <div className="security-card-title"><Github size={15}/><h3>GitHub repository</h3><span className={`security-badge ${status?.connected ? 'good' : 'muted'}`}>{status?.connected ? `Connected · ${status.account}` : status?.configured ? 'Not connected' : 'Not configured'}</span></div>
    <p className="security-copy">Import a bounded, read-only snapshot pinned to an immutable commit. Repository scripts and tests are never run.</p>
    {error && <div className="security-inline-note error"><AlertCircle size={14}/>{error}</div>}
    {!status?.configured ? <div className="security-inline-note">{status?.message || 'Configure the GitHub App on the backend to enable repository imports.'}</div> : !status.connected ? <><a className="button secondary github-connect" href="/api/github/connect"><Github size={14}/>Connect GitHub</a><small className="github-note">Install this GitHub App in an account first. If GitHub reports no authorized installation, install it and connect again.{status.app_slug && <> <a href={`https://github.com/apps/${status.app_slug}/installations/new`} target="_blank" rel="noreferrer">Install {status.app_slug}</a>.</>}</small></> : <>
      {status.installations.length > 1 && <label className="github-installation-select">GitHub account<select value={connectionId} onChange={event => { setConnectionId(event.target.value); setRepoId(''); setRepos([]); setBranches([]) }}>{status.installations.map(item => <option key={item.id} value={item.id}>{item.login} · {item.type}</option>)}</select></label>}
      <div className="github-select-row"><label>Authorized repository<select value={repoId} onChange={event => void chooseRepo(event.target.value)}><option value="">Select a repository</option>{repos.map(repo => <option key={repo.id} value={repo.id}>{repo.full_name}{repo.default_branch ? ` · ${repo.default_branch}` : ''}</option>)}</select></label><label>Branch<select value={branch} onChange={event => setBranch(event.target.value)} disabled={!branches.length}><option value="">Select a branch</option>{branches.map(item => <option key={item.name} value={item.name}>{item.name}</option>)}</select></label><button className="button secondary" disabled={busy || !selectedRepo || !branch} onClick={() => void startImport()}>{busy ? 'Working…' : 'Import commit'}</button></div>
      <small className="github-note">GitHub permissions are read-only: repository contents and metadata. The selected branch is resolved to a commit SHA before import.</small>
    </>}
    {imports.length > 0 && <div className="github-import-list">{imports.map(row => <article className={`github-import-row ${row.id === selectedId ? 'selected' : ''}`} key={row.id}><div className="github-import-heading"><strong>{row.full_name}</strong><span className={`scan-status ${row.status}`}>{row.status.replace('_', ' ')}</span></div><div className="github-import-meta"><GitBranch size={13}/>{row.selected_branch} · <code>{row.commit_sha.slice(0, 12)}</code></div>{row.error_detail && <small className="github-error-detail">{row.error_detail}</small>}{(row.status === 'completed' || row.status === 'completed_partial') && <><small>{row.indexed_file_count} indexed · {row.skipped_file_count} skipped · scans: {row.supported_scan_types.join(', ') || 'none supported'}{row.status === 'completed_partial' ? ' · bounded subset' : ''}</small><button className="text-button" onClick={() => onSelect(row)}>{row.id === selectedId ? 'Selected scan source' : 'Use this snapshot for scans'}</button></>}{(row.status === 'failed' || row.status === 'unsupported') && <button className="text-button" disabled={busy} onClick={() => void retry(row)}><RefreshCw size={13}/>Retry</button>}<button className="tiny-icon github-remove" disabled={busy || row.status === 'queued' || row.status === 'running'} title="Remove imported snapshot" onClick={() => void remove(row)}><Trash2 size={14}/></button></article>)}</div>}
    <button className="text-button github-refresh" onClick={() => void refresh()}><RefreshCw size={13}/>Refresh GitHub status</button>
  </section>
}
