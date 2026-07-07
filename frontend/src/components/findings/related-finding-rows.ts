import { scanApi } from '@/api/scans'
import { Finding } from '@/types/scan'

/**
 * Structured form of a related-finding reference (as emitted for the
 * FindingDetailsModal "related findings" links). The synthetic display-id
 * formats are parsed exactly once here so the local-row match and the API
 * fallback below share a single source of truth for the format list.
 *
 * NOTE: an equivalent parser/resolver already lives in
 * analytics/related-finding (`resolveRelatedFinding`) and the badge
 * label dispatch lives in FindingDetailsModal; consolidating all three into a
 * shared lib helper is deferred to a later cross-file dedup phase — this copy
 * is kept in this module on purpose.
 */
type ParsedRelatedId =
    | { kind: 'outdated'; component: string }
    | { kind: 'quality'; component: string; version?: string }
    | { kind: 'license' }
    | { kind: 'eol'; component: string }
    | { kind: 'vulnerability'; component?: string; version?: string }
    | { kind: 'exact' }

function parseRelatedFindingId(id: string): ParsedRelatedId {
    // OUTDATED-{component}
    if (id.startsWith('OUTDATED-')) {
        return { kind: 'outdated', component: id.replace('OUTDATED-', '') }
    }
    // QUALITY:{component}:{version}
    if (id.startsWith('QUALITY:')) {
        const parts = id.split(':')
        return { kind: 'quality', component: parts[1] ?? '', version: parts[2] }
    }
    // LIC-{license}: the synthetic id encodes the license name, not a finding
    // id, so there is no reliable structured mapping to a single license
    // finding. Resolution relies on the exact-id match / API path instead of
    // selecting an arbitrary "first license finding".
    if (id.startsWith('LIC-')) {
        return { kind: 'license' }
    }
    // EOL-{component}-{cycle}: strip only the trailing cycle segment so
    // hyphenated component names (e.g. EOL-spring-boot-2) resolve to the full
    // component "spring-boot" rather than "spring".
    if (id.startsWith('EOL-')) {
        return { kind: 'eol', component: id.replace(/^EOL-/, '').replace(/-[^-]+$/, '') }
    }
    // component:version (vulnerabilities)
    if (id.includes(':') && !id.startsWith('AGG:')) {
        const [component, version] = id.split(':')
        return { kind: 'vulnerability', component, version }
    }
    return { kind: 'exact' }
}

/**
 * Resolve a related-finding reference against the already-loaded rows.
 * Prefers an exact id match, then falls back to the format-specific match.
 * Returns undefined for LIC-/unknown ids rather than guessing.
 */
export function resolveRelatedFindingInRows(rows: readonly Finding[], id: string): Finding | undefined {
    const exact = rows.find(f => f.id === id)
    if (exact) return exact

    const parsed = parseRelatedFindingId(id)
    switch (parsed.kind) {
        case 'outdated':
            return rows.find(f =>
                f.type === 'outdated' &&
                f.component?.toLowerCase() === parsed.component.toLowerCase()
            )
        case 'quality':
            return rows.find(f =>
                f.type === 'quality' &&
                f.component?.toLowerCase() === parsed.component.toLowerCase() &&
                (!parsed.version || f.version === parsed.version)
            )
        case 'eol':
            return parsed.component
                ? rows.find(f =>
                    f.type === 'eol' &&
                    f.component?.toLowerCase() === parsed.component.toLowerCase()
                )
                : undefined
        case 'vulnerability':
            return rows.find(f =>
                f.component?.toLowerCase() === parsed.component?.toLowerCase() &&
                f.version === parsed.version
            )
        case 'license':
        case 'exact':
        default:
            return undefined
    }
}

/**
 * Resolve a related-finding reference via the API when it is not in the
 * currently loaded rows (e.g. switching between quality/security tabs).
 */
export async function fetchRelatedFinding(scanId: string, id: string): Promise<Finding | undefined> {
    const parsed = parseRelatedFindingId(id)
    switch (parsed.kind) {
        case 'outdated': {
            const res = await scanApi.getFindings(scanId, { type: 'outdated', search: parsed.component, skip: 0, limit: 200 })
            return res.items.find(f => f.type === 'outdated' && f.component?.toLowerCase() === parsed.component.toLowerCase())
        }
        case 'quality': {
            const res = await scanApi.getFindings(scanId, { type: 'quality', search: parsed.component, skip: 0, limit: 200 })
            return res.items.find(f => f.type === 'quality' && f.component?.toLowerCase() === parsed.component.toLowerCase() && (!parsed.version || f.version === parsed.version))
        }
        case 'license': {
            const res = await scanApi.getFindings(scanId, { type: 'license', search: id, skip: 0, limit: 200 })
            return res.items.find(f => f.id === id) || res.items[0]
        }
        case 'eol': {
            const res = await scanApi.getFindings(scanId, { type: 'eol', search: parsed.component, skip: 0, limit: 200 })
            return res.items.find(f => f.type === 'eol' && f.component?.toLowerCase() === parsed.component.toLowerCase())
        }
        case 'vulnerability': {
            const res = await scanApi.getFindings(scanId, { type: 'vulnerability', search: parsed.component, skip: 0, limit: 200 })
            return res.items.find(f => f.type === 'vulnerability' && f.component?.toLowerCase() === parsed.component?.toLowerCase() && f.version === parsed.version)
        }
        case 'exact':
        default: {
            const res = await scanApi.getFindings(scanId, { search: id, skip: 0, limit: 200 })
            return res.items.find(f => f.id === id) || res.items[0]
        }
    }
}
