import { scanApi } from '@/api/scans'
import { Finding } from '@/types/scan'

/** Rows one resolution reads before it reports that it looked at a window instead of the scan. */
export const RELATED_FINDING_SEARCH_LIMIT = 200

/** Why a related-finding reference did not open, so "no such finding" and "not in the window" differ. */
export type RelatedFindingLookup =
    | { status: 'found'; finding: Finding }
    | { status: 'missing' }
    | { status: 'beyond-window'; searched: number; matched: number }

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

/** The window a search read against the matches it had, so a miss can name which of the two it is. */
export function lookupOutcome(finding: Finding | undefined, matched: number): RelatedFindingLookup {
    if (finding) return { status: 'found', finding }
    if (matched > RELATED_FINDING_SEARCH_LIMIT) {
        return { status: 'beyond-window', searched: RELATED_FINDING_SEARCH_LIMIT, matched }
    }
    return { status: 'missing' }
}

/** Resolve a related-finding reference via the API when it is not in the loaded rows. */
export async function fetchRelatedFinding(scanId: string, id: string): Promise<RelatedFindingLookup> {
    const parsed = parseRelatedFindingId(id)
    const search = parsed.kind === 'license' || parsed.kind === 'exact' ? id : parsed.component
    const type = parsed.kind === 'exact' ? undefined : parsed.kind
    const res = await scanApi.getFindings(scanId, {
        type,
        search,
        skip: 0,
        limit: RELATED_FINDING_SEARCH_LIMIT,
    })

    return lookupOutcome(pickMatch(res.items, id, parsed), res.total)
}

function pickMatch(items: Finding[], id: string, parsed: ParsedRelatedId): Finding | undefined {
    switch (parsed.kind) {
        case 'outdated':
        case 'eol':
        case 'quality':
            return items.find(f =>
                f.type === parsed.kind &&
                f.component?.toLowerCase() === parsed.component.toLowerCase() &&
                (parsed.kind !== 'quality' || !parsed.version || f.version === parsed.version)
            )
        case 'vulnerability':
            return items.find(f =>
                f.type === 'vulnerability' &&
                f.component?.toLowerCase() === parsed.component?.toLowerCase() &&
                f.version === parsed.version
            )
        case 'license':
        case 'exact':
        default:
            return items.find(f => f.id === id) || items[0]
    }
}
