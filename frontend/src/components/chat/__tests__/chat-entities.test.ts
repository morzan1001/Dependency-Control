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

    expect(out).toBe(
      'The scan surfaced [CVE-2024-12345](/projects/p1/scans/s1?finding=CVE-2024-12345) in your build.',
    );
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

  it('links every owning team a project row names, not only its first', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({
        project_id: 'p9',
        project_name: 'acme-api',
        teams: [
          { id: 't1', name: 'Payments' },
          { id: 't2', name: 'Platform' },
        ],
      }),
    ]);
    const out = linkifyAssistantMarkdown('Payments and Platform own acme-api today.', entities);
    expect(out).toBe('[Payments](/teams) and [Platform](/teams) own [acme-api](/projects/p9) today.');
  });

  it('links a finding by the finding_id the findings search resolves, not its row uuid', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({
        findings: [
          {
            id: '6f1c0e2a-9b7d-4c4e-8a51-2f3d4e5a6b7c',
            finding_id: 'github.com/docker/docker:v20.10.7+incompatible',
            project_id: 'p1',
            scan_id: 's1',
            cve: 'CVE-2021-41091',
          },
        ],
      }),
    ]);
    expect(linkifyAssistantMarkdown('Fix CVE-2021-41091 first', entities)).toBe(
      'Fix [CVE-2021-41091](/projects/p1/scans/s1?finding=github.com%2Fdocker%2Fdocker%3Av20.10.7%2Bincompatible) first',
    );
  });

  it('links a CVE two findings share once', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({
        findings: [
          { project_id: 'p1', scan_id: 's1', finding_id: 'log4j-core:2.14.1', cve: 'CVE-2021-44228' },
          { project_id: 'p1', scan_id: 's1', finding_id: 'log4j-api:2.14.1', cve: 'CVE-2021-44228' },
        ],
      }),
    ]);
    expect(linkifyAssistantMarkdown('Both carry CVE-2021-44228 today', entities)).toBe(
      'Both carry [CVE-2021-44228](/projects/p1/scans/s1?finding=log4j-core%3A2.14.1) today',
    );
  });

  it('links a name that is part of a longer entity outside that entity only', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({
        project_id: 'p2',
        project_name: 'lodash',
        findings: [
          { project_id: 'p2', scan_id: 's2', finding_id: 'lodash:4.17.20', component: 'lodash', version: '4.17.20' },
        ],
      }),
    ]);
    expect(linkifyAssistantMarkdown('Bump lodash@4.17.20 in lodash', entities)).toBe(
      'Bump [lodash@4.17.20](/projects/p2/scans/s2?finding=lodash%3A4.17.20) in [lodash](/projects/p2)',
    );
  });

  it('links a mention that ends a sentence', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({ project_id: 'p9', project_name: 'acme-api' }),
    ]);
    expect(linkifyAssistantMarkdown('The riskiest project is acme-api.', entities)).toBe(
      'The riskiest project is [acme-api](/projects/p9).',
    );
  });

  it('leaves a name followed by .word unlinked', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({ project_id: 'p9', project_name: 'acme-api' }),
    ]);
    expect(linkifyAssistantMarkdown('See acme-api.example.com and acme-api.v2 today.', entities)).toBe(
      'See acme-api.example.com and acme-api.v2 today.',
    );
  });

  it('links a mention whose case differs from the entity', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({ project_id: 'p9', project_name: 'acme-api' }),
    ]);
    expect(linkifyAssistantMarkdown('Check ACME-API now.', entities)).toBe(
      'Check [acme-api](/projects/p9) now.',
    );
  });

  it('links an entity whose text holds regex metacharacters', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({
        project_id: 'p1',
        scan_id: 's1',
        finding_id: 'github.com/docker/docker:v20.10.7+incompatible',
        component: 'github.com/docker/docker',
        version: 'v20.10.7+incompatible',
      }),
    ]);
    expect(
      linkifyAssistantMarkdown('Bump github.com/docker/docker@v20.10.7+incompatible now', entities),
    ).toBe(
      'Bump [github.com/docker/docker@v20.10.7+incompatible](/projects/p1/scans/s1?finding=github.com%2Fdocker%2Fdocker%3Av20.10.7%2Bincompatible) now',
    );
  });

  it('links project entity mentions', () => {
    const entities = collectEntitiesFromToolCalls([
      toolCall({ project_id: 'p9', project_name: 'acme-api' }),
    ]);
    const out = linkifyAssistantMarkdown('Check acme-api now.', entities);
    expect(out).toBe('Check [acme-api](/projects/p9) now.');
  });
});
