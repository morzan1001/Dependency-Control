import * as React from 'react'
import { useState, useRef, useEffect } from 'react'
import { usePackageSuggestions } from '@/hooks/queries/use-broadcast'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { Check, Loader2 } from 'lucide-react'
import { useDebounce } from '@/hooks/use-debounce'

interface PackageAutocompleteProps {
  value: string
  onValueChange: (value: string) => void
  placeholder?: string
  className?: string
}

export function PackageAutocomplete({
  value,
  onValueChange,
  placeholder = "Search packages...",
  className,
}: PackageAutocompleteProps) {
  const [open, setOpen] = useState(false)
  const [inputValue, setInputValue] = useState(value)
  const debouncedSearch = useDebounce(inputValue, 300)
  const containerRef = useRef<HTMLDivElement>(null)

  // Sync internal input with prop value changes
  useEffect(() => {
     setInputValue(value)
  }, [value])

  // Fetch suggestions
  const { data: suggestions, isLoading } = usePackageSuggestions(debouncedSearch)

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelect = (pkgName: string) => {
    onValueChange(pkgName)
    setInputValue(pkgName)
    setOpen(false)
  }
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = e.target.value;
      setInputValue(val)
      onValueChange(val) 
      setOpen(true)
  }

  return (
    <div className="relative w-full" ref={containerRef}>
      <Input
        value={inputValue}
        onChange={handleInputChange}
        onFocus={() => setOpen(true)}
        placeholder={placeholder}
        className={cn("w-full", className)}
        autoComplete="off"
      />
      
      {open && inputValue.length >= 2 && (
        <div className="absolute top-full z-10 w-full mt-1 overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md animate-in fade-in-0 zoom-in-95">
           {isLoading && (
              <div className="p-2 text-sm text-muted-foreground flex items-center gap-2">
                 <Loader2 className="h-4 w-4 animate-spin" /> Looking up...
              </div>
           )}
           
           {!isLoading && suggestions && suggestions.length > 0 && (
              <div className="max-h-[200px] overflow-y-auto p-1">
                 {suggestions.map((pkg) => (
                    <div
                       key={pkg}
                       className={cn(
                          "relative flex cursor-default select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none hover:bg-accent hover:text-accent-foreground cursor-pointer"
                       )}
                       onClick={() => handleSelect(pkg)}
                    >
                       <span className="flex-1 truncate">{pkg}</span>
                       {pkg === inputValue && <Check className="ml-auto h-4 w-4" />}
                    </div>
                 ))}
              </div>
           )}
           
           {!isLoading && (!suggestions || suggestions.length === 0) && (
             <div className="p-2 text-sm text-muted-foreground italic">
                No found, using custom input.
             </div>
           )}
        </div>
      )}
    </div>
  )
}
