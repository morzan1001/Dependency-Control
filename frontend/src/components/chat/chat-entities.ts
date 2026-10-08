import type { ToolCall } from '@/types/chat';
import { advisoryUrl } from '@/lib/finding-utils';

// Text mapping to a concrete app entity, used to linkify plain mentions in answers.
export interface LinkableEntity {
  readonly text: string;
  readonly markdown: string;
}

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;

type AddEntity = (text: string, markdown: string) => void;

function collectProjectEntity(obj: Record<string, unknown>, add: AddEntity): void {
  if (typeof obj.project_name === 'string' && typeof obj.project_id === 'string') {
    add(obj.project_name, `[${obj.project_name}](/projects/${obj.project_id})`);
  }
}

function collectTeamEntities(obj: Record<string, unknown>, add: AddEntity): void {
  if (!Array.isArray(obj.teams)) return;
  for (const owner of obj.teams) {
    const ref = owner as Record<string, unknown>;
    if (typeof ref?.id === 'string' && typeof ref.name === 'string') {
      add(ref.name, `[${ref.name}](/teams)`);
    }
  }
}

function collectFindingEntities(obj: Record<string, unknown>, add: AddEntity): void {
  if (
    typeof obj.project_id !== 'string' ||
    typeof obj.scan_id !== 'string' ||
    typeof obj.finding_id !== 'string'
  ) {
    return;
  }
  const href = `/projects/${obj.project_id}/scans/${obj.scan_id}?finding=${encodeURIComponent(obj.finding_id)}`;
  if (typeof obj.cve === 'string' && obj.cve) {
    add(obj.cve, `[${obj.cve}](${href})`);
  }
  if (typeof obj.component === 'string' && obj.component) {
    const version = typeof obj.version === 'string' ? obj.version : '';
    const label = version ? `${obj.component}@${version}` : obj.component;
    add(label, `[${label}](${href})`);
  }
}

function collectFromToolResult(result: unknown, add: AddEntity): void {
  if (!result || typeof result !== 'object') return;
  if (Array.isArray(result)) {
    for (const item of result) collectFromToolResult(item, add);
    return;
  }
  const obj = result as Record<string, unknown>;
  collectProjectEntity(obj, add);
  collectTeamEntities(obj, add);
  collectFindingEntities(obj, add);
  for (const value of Object.values(obj)) {
    collectFromToolResult(value, add);
  }
}

/** Extract linkable entities from a set of tool calls (both stored + streaming), one per text. */
export function collectEntitiesFromToolCalls(
  toolCalls: ReadonlyArray<ToolCall>,
): LinkableEntity[] {
  const byText = new Map<string, LinkableEntity>();
  const add: AddEntity = (text, markdown) => {
    const key = text.toLowerCase();
    if (text && !byText.has(key)) byText.set(key, { text, markdown });
  };
  for (const tc of toolCalls) {
    collectFromToolResult(tc.result, add);
  }
  return Array.from(byText.values());
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
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

  const markdownByText = new Map(entities.map((e) => [e.text.toLowerCase(), e.markdown]));
  // One pass, longest first: "acme-api-v2" wins over "acme-api" and no entity lands inside another's link.
  const alternation = [...markdownByText.keys()]
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp)
    .join('|');
  // Whole-token match; boundaries exclude `/` and `.` to skip URLs and versions, a sentence-ending `.` still counts.
  const entityPattern = alternation
    ? new RegExp(String.raw`(^|[^A-Za-z0-9_\-./])(${alternation})(?=\.?(?:[^A-Za-z0-9_\-./]|$))`, 'gi')
    : null;

  const linkifyCves = (text: string): string =>
    text.replace(CVE_PATTERN, (cve) => {
      const upper = cve.toUpperCase();
      return `[${upper}](${advisoryUrl(upper)})`;
    });

  const linkifyText = (segment: string): string => {
    const result = entityPattern
      ? segment.replace(
          entityPattern,
          (_match, lead: string, text: string) => `${lead}${markdownByText.get(text.toLowerCase())}`,
        )
      : segment;
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
