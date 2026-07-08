import { ComponentFinding } from '@/types/analytics'

// Resolve a related-finding reference to a finding in the list, handling the backend's synthetic display-id formats as well as exact ids.
export function resolveRelatedFinding(
  findings: ComponentFinding[],
  id: string,
): ComponentFinding | undefined {
  const exact = findings.find(f => f.id === id)
  if (exact) return exact

  if (id.startsWith("OUTDATED-")) {
    const comp = id.replace("OUTDATED-", "")
    return findings.find(f =>
      f.type === "outdated" &&
      f.component?.toLowerCase() === comp.toLowerCase()
    )
  }

  if (id.startsWith("QUALITY:")) {
    const parts = id.split(":")
    if (parts.length < 2) return undefined
    const comp = parts[1]
    const ver = parts[2]
    return findings.find(f =>
      f.type === "quality" &&
      f.component?.toLowerCase() === comp?.toLowerCase() &&
      (!ver || f.version === ver)
    )
  }

  // LIC- ids encode a license name, not a finding id, so there is no reliable single-finding mapping.
  if (id.startsWith("LIC-")) {
    return undefined
  }

  // Strip only the trailing cycle segment so hyphenated components (e.g. EOL-spring-boot-2 -> spring-boot) resolve correctly.
  if (id.startsWith("EOL-")) {
    const comp = id.replace(/^EOL-/, "").replace(/-[^-]+$/, "")
    if (!comp) return undefined
    return findings.find(f =>
      f.type === "eol" &&
      f.component?.toLowerCase() === comp.toLowerCase()
    )
  }

  if (id.includes(":") && !id.startsWith("AGG:")) {
    const [comp, ver] = id.split(":")
    return findings.find(f =>
      f.component?.toLowerCase() === comp?.toLowerCase() &&
      f.version === ver
    )
  }

  return undefined
}
