import type { ToolCall } from '@/types/chat';
import { advisoryUrl } from '@/lib/finding-utils';

// Text mapping to a concrete app entity, used to linkify plain mentions in answers.
export interface LinkableEntity {
  readonly text: string;
  readonly markdown: string;
  // Longer text wins, so "acme-api-v2" is preferred over "acme-api".
  readonly priority: number;
}

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;

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
    const existing = out.get(key);
    if (!existing || existing.priority < priority) {
      out.set(key, { text, markdown, priority });
    }
  };

  if (typeof obj.project_name === 'string' && typeof obj.project_id === 'string') {
    add(
      `project:${obj.project_id}`,
      obj.project_name,
      `[${obj.project_name}](/projects/${obj.project_id})`,
      obj.project_name.length,
    );
  }
  if (typeof obj.team_name === 'string' && typeof obj.team_id === 'string') {
    add(
      `team:${obj.team_id}`,
      obj.team_name,
      `[${obj.team_name}](/teams/${obj.team_id})`,
      obj.team_name.length,
    );
  }
  // Finding deep-link: prefer the UUID `id`, fall back to `finding_id`.
  if (
    typeof obj.project_id === 'string' &&
    typeof obj.scan_id === 'string' &&
    (typeof obj.id === 'string' || typeof obj.finding_id === 'string')
  ) {
    const fid = typeof obj.id === 'string' ? obj.id : (obj.finding_id as string);
    const href = `/projects/${obj.project_id}/scans/${obj.scan_id}?finding=${encodeURIComponent(fid)}`;
    // Prefer a CVE anchor, else component@version.
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

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Linkify known-entity mentions (whole-word, case-insensitive) plus any CVE ID,
// skipping text already inside a Markdown link or code span.
export function linkifyAssistantMarkdown(
  content: string,
  entities: ReadonlyArray<LinkableEntity>,
): string {
  if (!content) return content;

  // Split on code spans/fences/existing links (captured) so only plain-text
  // segments at even indices get rewritten.
  const skipPattern = /(\[[^\]]*\]\([^)]*\)|```[\s\S]*?```|`[^`]*`)/g;
  const segments = content.split(skipPattern);

  // Longest first so "acme-api-v2" wins over "acme-api".
  const sorted = [...entities].sort((a, b) => b.priority - a.priority);

  const linkifyCves = (text: string): string =>
    text.replace(CVE_PATTERN, (cve) => {
      const upper = cve.toUpperCase();
      return `[${upper}](${advisoryUrl(upper)})`;
    });

  const linkifyText = (segment: string): string => {
    let result = segment;
    for (const entity of sorted) {
      const escaped = escapeRegExp(entity.text);
      // Whole-token match; boundaries exclude `/` and `.` to skip URLs and versions.
      const regex = new RegExp(
        `(^|[^A-Za-z0-9_\\-./])(${escaped})(?=[^A-Za-z0-9_\\-./]|$)`,
        'gi',
      );
      result = result.replace(regex, (_match, lead: string) => {
        return `${lead}${entity.markdown}`;
      });
    }
    // Re-split before the CVE pass so it skips links the entity pass just inserted.
    return result
      .split(skipPattern)
      .map((seg, idx) => (idx % 2 === 0 ? linkifyCves(seg) : seg))
      .join('');
  };

  for (let i = 0; i < segments.length; i += 1) {
    if (i % 2 === 0) {
      segments[i] = linkifyText(segments[i]);
    }
  }
  return segments.join('');
}
