import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

interface SecretInputProps {
  readonly id: string
  readonly value: string | null | undefined
  readonly configured: boolean
  readonly onChange: (value: string | null) => void
  readonly placeholder?: string
}

// Secret values are never echoed by the API; `configured` drives the placeholder
// so a stored secret doesn't look missing. null asks the save to clear it.
export function SecretInput({ id, value, configured, onChange, placeholder }: SecretInputProps) {
  const removing = value === null
  let effectivePlaceholder = placeholder
  if (removing) {
    effectivePlaceholder = "Removed when you save"
  } else if (configured && !value) {
    effectivePlaceholder = "Configured — enter a new value to replace"
  }
  return (
    <div className="flex gap-2">
      <Input
        id={id}
        type="password"
        placeholder={effectivePlaceholder}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
      />
      {configured && (
        <Button type="button" variant="outline" onClick={() => onChange(removing ? '' : null)}>
          {removing ? 'Undo' : 'Remove'}
        </Button>
      )}
    </div>
  )
}
