import { Input } from "@/components/ui/input"

interface SecretInputProps {
  readonly id: string
  readonly value: string
  readonly configured: boolean
  readonly onChange: (value: string) => void
  readonly placeholder?: string
}

// Secret values are never echoed by the API; `configured` drives the placeholder
// so a stored secret doesn't look missing.
export function SecretInput({ id, value, configured, onChange, placeholder }: SecretInputProps) {
  const effectivePlaceholder = configured && !value
    ? "Configured — enter a new value to replace"
    : placeholder
  return (
    <Input
      id={id}
      type="password"
      placeholder={effectivePlaceholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}
