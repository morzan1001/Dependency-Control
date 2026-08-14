import { toast } from 'sonner'

function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  window.URL.revokeObjectURL(url)
  a.remove()
}

export async function downloadFile(
  fetchBlob: () => Promise<Blob>,
  filename: string,
  errorMsg: string,
) {
  try {
    triggerBrowserDownload(await fetchBlob(), filename)
  } catch {
    toast.error(errorMsg)
  }
}

/** Download honouring the server's filename; falls back to a zip extension when the payload is a zip. */
export async function downloadServerFile(
  fetchFile: () => Promise<{ blob: Blob; filename: string | null }>,
  fallbackFilename: string,
  errorMsg: string,
) {
  try {
    const { blob, filename } = await fetchFile()
    let name = filename ?? fallbackFilename
    if (!filename && blob.type === 'application/zip' && !name.endsWith('.zip')) {
      name = `${name.replace(/\.[^.]+$/, '')}.zip`
    }
    triggerBrowserDownload(blob, name)
  } catch {
    toast.error(errorMsg)
  }
}

export function filenameFromContentDisposition(header: string | undefined | null): string | null {
  if (!header) return null
  const match = /filename="?([^";]+)"?/i.exec(header)
  return match ? match[1] : null
}
