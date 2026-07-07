import { describe, it, expect } from 'vitest';

import {
  collectEntitiesFromToolCalls,
  linkifyAssistantMarkdown,
} from '../chat-entities';
import type { ToolCall } from '@/types/chat';

const toolCall = (result: Record<string, unknown>): ToolCall => ({
  tool_name: 'test',
  arguments: {},
  result,
  duration_ms: 1,
});

describe('linkifyAssistantMarkdown', () => {
  // Regression (audit finding #1): the CVE post-pass used to run over the
  // whole string AFTER the entity pass had inserted Markdown links, so a CVE
  // used as a finding anchor got re-linkified inside the link it had just
  // become — yielding nested, broken Markdown and a dead deep-link.
  it('does not re-linkify a CVE inside a link the entity pass inserted', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({
        project_id: 'p1',
        scan_id: 's1',
        finding_id: 'CVE-2024-12345',
        cve: 'CVE-2024-12345',
      }),
    ]);

    const out = linkifyAssistantMarkdown(
      'The scan surfaced CVE-2024-12345 in your build.',
      entities,
    );

    // The mention becomes exactly the scan-drawer deep link, once.
    expect(out).toBe(
      'The scan surfaced [CVE-2024-12345](/projects/p1/scans/s1?finding=CVE-2024-12345) in your build.',
    );
    // No nested Markdown and no NVD rewrite of the entity link.
    expect(out).not.toContain('nvd.nist.gov');
    expect(out).not.toContain('[[');
    expect(out).not.toContain('=[CVE');
  });

  it('still linkifies a bare CVE (not a known entity) to NVD', () => {
    const out = linkifyAssistantMarkdown('See CVE-2021-44228 for details.', []);
    expect(out).toBe(
      'See [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) for details.',
    );
  });

  it('leaves CVEs inside pre-existing links and code spans untouched', () => {
    const content =
      'Ref [CVE-2020-0001](http://x) and `CVE-2020-0002` stay put.';
    expect(linkifyAssistantMarkdown(content, [])).toBe(content);
  });

  it('links project entity mentions', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({ project_id: 'p9', project_name: 'acme-api' }),
    ]);
    const out = linkifyAssistantMarkdown('Check acme-api now.', entities);
    expect(out).toBe('Check [acme-api](/projects/p9) now.');
  });
});
