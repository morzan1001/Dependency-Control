import { ComponentFinding } from '@/types/analytics'

/**
 * Resolve a related-finding reference (as emitted for the FindingDetailsModal
 * "related findings" links) to a finding in the current list. Handles the
 * synthetic display-id formats the backend uses in addition to exact ids.
 */
export function resolveRelatedFinding(
  findings: ComponentFinding[],
  id: string,
): ComponentFinding | undefined {
  // First try exact match by ID
  const exact = findings.find(f => f.id === id)
  if (exact) return exact

  // Handle OUTDATED-{component} format
  if (id.startsWith("OUTDATED-")) {
    const comp = id.replace("OUTDATED-", "")
    return findings.find(f =>
      f.type === "outdated" &&
      f.component?.toLowerCase() === comp.toLowerCase()
    )
  }

  // Handle QUALITY:{component}:{version} format
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

  // Handle LIC-{license} format. The synthetic id encodes the license name,
  // not a finding id, so there is no reliable structured mapping to a single
  // license finding - fall back to the exact-id match above rather than
  // selecting an arbitrary "first license finding".
  if (id.startsWith("LIC-")) {
    return undefined
  }

  // Handle EOL-{component}-{cycle} format. Strip only the trailing cycle
  // segment so hyphenated component names (e.g. EOL-spring-boot-2) resolve
  // to the full component "spring-boot" rather than "spring".
  if (id.startsWith("EOL-")) {
    const comp = id.replace(/^EOL-/, "").replace(/-[^-]+$/, "")
    if (!comp) return undefined
    return findings.find(f =>
      f.type === "eol" &&
      f.component?.toLowerCase() === comp.toLowerCase()
    )
  }

  // Handle component:version format (vulnerabilities)
  if (id.includes(":") && !id.startsWith("AGG:")) {
    const [comp, ver] = id.split(":")
    return findings.find(f =>
      f.component?.toLowerCase() === comp?.toLowerCase() &&
      f.version === ver
    )
  }

  return undefined
}
