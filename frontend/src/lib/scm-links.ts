export type ScmProvider = 'github' | 'gitlab'

function normalizeBaseUrl(url?: string | null): string | null {
  if (!url) return null
  const trimmed = url.trim()
  if (!trimmed) return null
  return trimmed.replace(/\/+$/, '')
}

function encodeRef(ref: string): string {
  return encodeURIComponent(ref).replace(/%2F/g, '/')
}

export function detectScmProvider(params: {
  projectUrl?: string | null
  pipelineUrl?: string | null
}): ScmProvider | null {
  const projectUrl = params.projectUrl?.toLowerCase() || ''
  const pipelineUrl = params.pipelineUrl?.toLowerCase() || ''

  if (projectUrl.includes('github.com') || pipelineUrl.includes('/actions/runs/')) return 'github'
  if (projectUrl.includes('gitlab') || pipelineUrl.includes('/-/pipelines/')) return 'gitlab'

  return null
}

export function buildBranchUrl(params: {
  projectUrl?: string | null
  pipelineUrl?: string | null
  branch?: string | null
}): string | null {
  const base = normalizeBaseUrl(params.projectUrl)
  const branch = params.branch?.trim()
  if (!base || !branch) return null

  const provider = detectScmProvider({ projectUrl: base, pipelineUrl: params.pipelineUrl })
  if (provider === 'github') return `${base}/tree/${encodeRef(branch)}`
  if (provider === 'gitlab') return `${base}/-/tree/${encodeRef(branch)}`
  return null
}

export function buildCommitUrl(params: {
  projectUrl?: string | null
  pipelineUrl?: string | null
  commitHash?: string | null
}): string | null {
  const base = normalizeBaseUrl(params.projectUrl)
  const commitHash = params.commitHash?.trim()
  if (!base || !commitHash) return null

  const provider = detectScmProvider({ projectUrl: base, pipelineUrl: params.pipelineUrl })
  if (provider === 'github') return `${base}/commit/${commitHash}`
  if (provider === 'gitlab') return `${base}/-/commit/${commitHash}`
  return null
}

export function buildPipelineUrl(params: {
  projectUrl?: string | null
  pipelineUrl?: string | null
  pipelineId?: number | string | null
}): string | null {
  const provided = normalizeBaseUrl(params.pipelineUrl)
  if (provided) return provided

  const base = normalizeBaseUrl(params.projectUrl)
  if (!base) return null

  const pipelineId = params.pipelineId
  if (pipelineId === undefined || pipelineId === null || pipelineId === '') return null

  const provider = detectScmProvider({ projectUrl: base, pipelineUrl: params.pipelineUrl })
  if (provider === 'github') return `${base}/actions/runs/${pipelineId}`
  if (provider === 'gitlab') return `${base}/-/pipelines/${pipelineId}`

  return null
}

export function buildFileUrl(params: {
  projectUrl?: string | null
  pipelineUrl?: string | null
  commitHash?: string | null
  branch?: string | null
  filePath?: string | null
  startLine?: number | null
  endLine?: number | null
}): string | null {
  const base = normalizeBaseUrl(params.projectUrl)
  const filePath = params.filePath?.trim()
  if (!base || !filePath) return null

  const ref = params.commitHash?.trim() || params.branch?.trim()
  if (!ref) return null

  const provider = detectScmProvider({ projectUrl: base, pipelineUrl: params.pipelineUrl })
  const cleanPath = filePath.replace(/^\.?\//, '')

  let lineFragment = ''
  if (params.startLine) {
    if (provider === 'github') {
      lineFragment = `#L${params.startLine}`
      if (params.endLine && params.endLine !== params.startLine) {
        lineFragment += `-L${params.endLine}`
      }
    } else if (provider === 'gitlab') {
      lineFragment = `#L${params.startLine}`
      if (params.endLine && params.endLine !== params.startLine) {
        lineFragment += `-${params.endLine}`
      }
    }
  }

  if (provider === 'github') {
    return `${base}/blob/${encodeRef(ref)}/${cleanPath}${lineFragment}`
  }
  if (provider === 'gitlab') {
    return `${base}/-/blob/${encodeRef(ref)}/${cleanPath}${lineFragment}`
  }

  return null
}
