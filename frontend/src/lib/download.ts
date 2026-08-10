import { toast } from 'sonner'

export async function downloadFile(
  fetchBlob: () => Promise<Blob>,
  filename: string,
  errorMsg: string,
) {
  try {
    const blob = await fetchBlob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    a.remove()
  } catch {
    toast.error(errorMsg)
  }
}
