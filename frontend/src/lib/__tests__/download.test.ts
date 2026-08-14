import { describe, it, expect, vi, beforeEach } from 'vitest'
import { downloadServerFile, filenameFromContentDisposition } from '../download'

describe('filenameFromContentDisposition', () => {
  it('parses a quoted filename', () => {
    expect(filenameFromContentDisposition('attachment; filename="project_p1_sboms.zip"')).toBe(
      'project_p1_sboms.zip',
    )
  })

  it('parses an unquoted filename', () => {
    expect(filenameFromContentDisposition('attachment; filename=project_p1_sbom.json')).toBe(
      'project_p1_sbom.json',
    )
  })

  it('returns null when absent', () => {
    expect(filenameFromContentDisposition(undefined)).toBeNull()
  })
})

describe('downloadServerFile', () => {
  let anchorDownload: string | undefined

  beforeEach(() => {
    anchorDownload = undefined
    window.URL.createObjectURL = vi.fn(() => 'blob:url')
    window.URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      anchorDownload = this.download
    })
  })

  it('uses the server-provided filename', async () => {
    await downloadServerFile(
      async () => ({ blob: new Blob(['{}'], { type: 'application/zip' }), filename: 'server-name.zip' }),
      'fallback.json',
      'err',
    )
    expect(anchorDownload).toBe('server-name.zip')
  })

  it('swaps the fallback extension to .zip when the payload is a zip and no filename was sent', async () => {
    await downloadServerFile(
      async () => ({ blob: new Blob(['pk'], { type: 'application/zip' }), filename: null }),
      'project-x-sbom.json',
      'err',
    )
    expect(anchorDownload).toBe('project-x-sbom.zip')
  })

  it('keeps the fallback for json payloads', async () => {
    await downloadServerFile(
      async () => ({ blob: new Blob(['{}'], { type: 'application/json' }), filename: null }),
      'project-x-sbom.json',
      'err',
    )
    expect(anchorDownload).toBe('project-x-sbom.json')
  })
})
