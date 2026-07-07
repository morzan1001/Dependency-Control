import { scanApi } from '@/api/scans'
import { Finding } from '@/types/scan'

type ParsedRelatedId =
    | { kind: 'outdated'; component: string }
    | { kind: 'quality'; component: string; version?: string }
    | { kind: 'license' }
    | { kind: 'eol'; component: string }
    | { kind: 'vulnerability'; component?: string; version?: string }
    | { kind: 'exact' }

function parseRelatedFindingId(id: string): ParsedRelatedId {
    if (id.startsWith('OUTDATED-')) {
        return { kind: 'outdated', component: id.replace('OUTDATED-', '') }
    }
    if (id.startsWith('QUALITY:')) {
        const parts = id.split(':')
        return { kind: 'quality', component: parts[1] ?? '', version: parts[2] }
    }
    // LIC- encodes the license name, not a finding id; resolve via exact-id/API instead.
    if (id.startsWith('LIC-')) {
        return { kind: 'license' }
    }
    // Strip only the trailing cycle segment so hyphenated names (EOL-spring-boot-2) resolve to "spring-boot".
    if (id.startsWith('EOL-')) {
        return { kind: 'eol', component: id.replace(/^EOL-/, '').replace(/-[^-]+$/, '') }
    }
    if (id.includes(':') && !id.startsWith('AGG:')) {
        const [component, version] = id.split(':')
        return { kind: 'vulnerability', component, version }
    }
    return { kind: 'exact' }
}

/** Resolve against already-loaded rows: exact id first, then format-specific match; undefined for LIC-/unknown. */
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

/** Resolve a related-finding reference via the API when it is not in the loaded rows. */
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
