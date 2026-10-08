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

// Ids are not unique per scan (a license id names only the license); cross-links join one package's findings.
function preferSamePackage<T extends Finding>(matches: readonly T[], from: Finding): T | undefined {
    const samePackage = matches.filter(f => f.component?.toLowerCase() === from.component?.toLowerCase())
    return samePackage.find(f => f.version === from.version) ?? samePackage[0] ?? matches[0]
}

/** Resolve a reference `from` holds: exact id first, then format-specific match; undefined for LIC-/unknown. */
export function resolveRelatedFindingInRows<T extends Finding>(rows: readonly T[], id: string, from: Finding): T | undefined {
    const exact = preferSamePackage(rows.filter(f => f.id === id), from)
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
                f.type === 'vulnerability' &&
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

// Every package with that license shares a license id, so the search names the package and keeps its row in the window.
function searchTerm(parsed: ParsedRelatedId, id: string, from: Finding): string | undefined {
    if (parsed.kind === 'license') return from.component
    return parsed.kind === 'exact' ? id : parsed.component
}

/** Resolve a related-finding reference via the API when it is not in the loaded rows. */
export async function fetchRelatedFinding(scanId: string, id: string, from: Finding): Promise<RelatedFindingLookup> {
    const parsed = parseRelatedFindingId(id)
    const res = await scanApi.getFindings(scanId, {
        type: parsed.kind === 'exact' ? undefined : parsed.kind,
        search: searchTerm(parsed, id, from),
        skip: 0,
        limit: RELATED_FINDING_SEARCH_LIMIT,
    })

    return lookupOutcome(resolveRelatedFindingInRows(res.items, id, from), res.total)
}
