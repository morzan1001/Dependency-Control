import { useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

interface InlineFieldFormProps {
  label: string;
  value: string;
  type?: React.HTMLInputTypeAttribute;
  isPending: boolean;
  onSave: (value: string) => void;
  onEdit?: () => void;
  children?: React.ReactNode;
}

export function InlineFieldForm({
  label,
  value,
  type,
  isPending,
  onSave,
  onEdit,
  children,
}: Readonly<InlineFieldFormProps>) {
  const inputId = useId();
  const [draft, setDraft] = useState(value);
  const next = draft.trim();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(next);
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-2">
      <Label htmlFor={inputId}>{label}</Label>
      <div className="flex gap-2">
        <Input
          id={inputId}
          type={type}
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            onEdit?.();
          }}
        />
        <Button
          type="submit"
          variant="outline"
          aria-label={`Save ${label.toLowerCase()}`}
          disabled={isPending || !next || next === value}
        >
          {isPending ? 'Saving...' : 'Save'}
        </Button>
      </div>
      {children}
    </form>
  );
}
