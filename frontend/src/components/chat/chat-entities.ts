import type { ToolCall } from '@/types/chat';

/**
 * A piece of text we know maps to a concrete entity in the app, so we can
 * turn plain mentions ("acme-api", "CVE-2024-12345") into links when the
 * assistant writes them in its answer.
 *
 * Only entities that actually appeared in a tool result are collected — this
 * prevents hallucinated link targets. If the model invents a project name
 * that wasn't in any tool response, it stays plain text.
 */
export interface LinkableEntity {
  /** Exact string the model might write. */
  readonly text: string;
  /** Full Markdown link to replace it with. */
  readonly markdown: string;
  /** Longer text wins, so "acme-api-v2" is preferred over "acme-api". */
  readonly priority: number;
}

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;

/** Walk a tool-result subtree and emit all `{id, name}` pairs we recognise. */
function collectFromToolResult(
  result: unknown,
  out: Map<string, LinkableEntity>,
): void {
  if (!result || typeof result !== 'object') return;
  if (Array.isArray(result)) {
    for (const item of result) collectFromToolResult(item, out);
    return;
  }
  const obj = result as Record<string, unknown>;

  const add = (key: string, text: string, markdown: string, priority: number) => {
    if (!text || !markdown) return;
    // Prefer the longer/more specific entry for the same target id.
    const existing = out.get(key);
    if (!existing || existing.priority < priority) {
      out.set(key, { text, markdown, priority });
    }
  };

  // Project
  if (typeof obj.project_name === 'string' && typeof obj.project_id === 'string') {
    add(
      `project:${obj.project_id}`,
      obj.project_name,
      `[${obj.project_name}](/projects/${obj.project_id})`,
      obj.project_name.length,
    );
  }
  // Team
  if (typeof obj.team_name === 'string' && typeof obj.team_id === 'string') {
    add(
      `team:${obj.team_id}`,
      obj.team_name,
      `[${obj.team_name}](/teams/${obj.team_id})`,
      obj.team_name.length,
    );
  }
  // Finding — deep-link to the scan page with the drawer auto-opened. We
  // need project_id + scan_id + a finding identifier. The backend emits
  // `id` (internal UUID) for vulnerability findings; `finding_id` for the
  // stable human string. Prefer the UUID (guaranteed unique); fall back
  // to finding_id so we still link license/quality items.
  if (
    typeof obj.project_id === 'string' &&
    typeof obj.scan_id === 'string' &&
    (typeof obj.id === 'string' || typeof obj.finding_id === 'string')
  ) {
    const fid = typeof obj.id === 'string' ? obj.id : (obj.finding_id as string);
    const href = `/projects/${obj.project_id}/scans/${obj.scan_id}?finding=${encodeURIComponent(fid)}`;
    // Prefer a CVE mention as link anchor (user-recognisable), then
    // component@version, then the raw finding_id as last resort.
    if (typeof obj.cve === 'string' && obj.cve) {
      add(
        `finding:${fid}:cve`,
        obj.cve,
        `[${obj.cve}](${href})`,
        obj.cve.length + 2,
      );
    }
    if (typeof obj.component === 'string' && obj.component) {
      const version = typeof obj.version === 'string' ? obj.version : '';
      const label = version ? `${obj.component}@${version}` : obj.component;
      add(
        `finding:${fid}:comp`,
        label,
        `[${label}](${href})`,
        label.length,
      );
    }
  }
  // Standalone project/team objects with id + name (no prefix)
  if (typeof obj.id === 'string' && typeof obj.name === 'string') {
    // Can't tell what entity type without more context — skip to avoid wrong links.
  }

  for (const value of Object.values(obj)) {
    collectFromToolResult(value, out);
  }
}

/** Extract linkable entities from a set of tool calls (both stored + streaming). */
export function collectEntitiesFromToolCalls(
  toolCalls: ReadonlyArray<ToolCall>,
): LinkableEntity[] {
  const map = new Map<string, LinkableEntity>();
  for (const tc of toolCalls) {
    collectFromToolResult(tc.result, map);
  }
  return Array.from(map.values());
}

/** Escape a string so it is safe to use inside a RegExp. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Post-process Markdown emitted by the model: turn mentions of known
 * entities into Markdown links. Matches are whole-word, case-insensitive,
 * and skip text that is already inside a Markdown link or code span.
 *
 * CVE IDs are linked to the NVD for external reference regardless of
 * whether they appeared in a tool result — the format alone is unambiguous.
 */
export function linkifyAssistantMarkdown(
  content: string,
  entities: ReadonlyArray<LinkableEntity>,
): string {
  if (!content) return content;

  // Split by code spans / code fences / existing links so we only touch
  // plain text. Anything that looks like [..](..) or `..` or ```..``` is
  // passed through untouched. We split on a regex with a capturing group
  // so the split result alternates plain-text | skipped-segment.
  const skipPattern = /(\[[^\]]*\]\([^)]*\)|```[\s\S]*?```|`[^`]*`)/g;
  const segments = content.split(skipPattern);

  // Sort entities longest first so "acme-api-v2" wins over "acme-api"
  // when both could match.
  const sorted = [...entities].sort((a, b) => b.priority - a.priority);

  const linkifyText = (segment: string): string => {
    let result = segment;
    for (const entity of sorted) {
      const escaped = escapeRegExp(entity.text);
      // Match as a whole token. Use non-word boundaries that also exclude `/`
      // and `.` so we don't rewrite text inside URLs or version strings.
      const regex = new RegExp(
        `(^|[^A-Za-z0-9_\\-./])(${escaped})(?=[^A-Za-z0-9_\\-./]|$)`,
        'gi',
      );
      result = result.replace(regex, (_match, lead: string) => {
        return `${lead}${entity.markdown}`;
      });
    }
    // Then linkify CVE IDs that weren't already linked
    result = result.replace(CVE_PATTERN, (cve) => {
      const upper = cve.toUpperCase();
      return `[${upper}](https://nvd.nist.gov/vuln/detail/${upper})`;
    });
    return result;
  };

  for (let i = 0; i < segments.length; i += 1) {
    // Even indices = plain text; odd indices = skipped segments (links / code).
    if (i % 2 === 0) {
      segments[i] = linkifyText(segments[i]);
    }
  }
  return segments.join('');
}
