import { useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

interface UsernameFormProps {
  username: string;
  isPending: boolean;
  onSave: (username: string) => void;
  onEdit?: () => void;
  children?: React.ReactNode;
}

export function UsernameForm({ username, isPending, onSave, onEdit, children }: Readonly<UsernameFormProps>) {
  const inputId = useId();
  const [value, setValue] = useState(username);
  const next = value.trim();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(next);
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-2">
      <Label htmlFor={inputId}>Username</Label>
      <div className="flex gap-2">
        <Input
          id={inputId}
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            onEdit?.();
          }}
        />
        <Button
          type="submit"
          variant="outline"
          aria-label="Save username"
          disabled={isPending || !next || next === username}
        >
          {isPending ? 'Saving...' : 'Save'}
        </Button>
      </div>
      {children}
    </form>
  );
}
