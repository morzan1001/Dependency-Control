import * as React from 'react'
import { useState, useRef, useCallback } from 'react'
import { useProjects } from '@/hooks/queries/use-projects'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { Check, ChevronsUpDown, Search, X, Folder } from 'lucide-react'
import { useDebounce } from '@/hooks/use-debounce'
import { useClickOutside } from '@/hooks/use-click-outside'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

interface ProjectComboboxProps {
  value: string
  onValueChange: (value: string) => void
  placeholder?: string
  className?: string
}

export function ProjectCombobox({
  value,
  onValueChange,
  placeholder = "Search projects...",
  className,
}: ProjectComboboxProps) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounce(search, DEBOUNCE_DELAY_MS)
  const containerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Fetch projects with search
  const { data: projectsData, isLoading } = useProjects(debouncedSearch || undefined, 1, 50)

  const projects = projectsData?.items || []
  const selectedProject = projects.find(p => p.id === value)

  // Close dropdown when clicking outside
  const handleClose = useCallback(() => setOpen(false), [])
  useClickOutside(containerRef, handleClose, open)

  // Handle keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setOpen(false)
    } else if (e.key === 'Enter' && projects.length === 1) {
      onValueChange(projects[0].id)
      setOpen(false)
      setSearch('')
    }
  }

  const handleSelect = (projectId: string) => {
    onValueChange(projectId)
    setOpen(false)
    setSearch('')
  }

  const handleClear = (e: React.MouseEvent) => {
    e.stopPropagation()
    onValueChange('')
    setSearch('')
  }

  return (
    <div ref={containerRef} className={cn("relative", className)}>
      {/* Trigger Button / Search Input */}
      <div className="relative">
        {open ? (
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              ref={inputRef}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={placeholder}
              className="pl-9 pr-8"
              autoFocus
            />
            {search && (
              <Button
                variant="ghost"
                size="icon"
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6"
                onClick={() => setSearch('')}
              >
                <X className="h-3 w-3" />
              </Button>
            )}
          </div>
        ) : (
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            onClick={() => {
              setOpen(true)
              setTimeout(() => inputRef.current?.focus(), 10)
            }}
            className="w-full justify-between font-normal"
          >
            <div className="flex items-center gap-2 truncate">
              {selectedProject ? (
                <>
                  <Folder className="h-4 w-4 text-muted-foreground shrink-0" />
                  <span className="truncate">{selectedProject.name}</span>
                </>
              ) : (
                <span className="text-muted-foreground">Select a project...</span>
              )}
            </div>
            <div className="flex items-center gap-1 shrink-0">
              {value && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-5 w-5"
                  onClick={handleClear}
                >
                  <X className="h-3 w-3" />
                </Button>
              )}
              <ChevronsUpDown className="h-4 w-4 text-muted-foreground" />
            </div>
          </Button>
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute z-50 mt-1 w-full rounded-md border bg-popover shadow-lg animate-in fade-in-0 zoom-in-95">
          <div className="max-h-[300px] overflow-y-auto p-1">
            {isLoading ? (
              <div className="space-y-1 p-1">
                {Array(5).fill(0).map((_, i) => (
                  <Skeleton key={i} className="h-9 w-full" />
                ))}
              </div>
            ) : projects.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                {search ? `No projects matching "${search}"` : 'No projects found'}
              </div>
            ) : (
              <div className="space-y-0.5">
                {projects.map((project) => (
                  <button
                    key={project.id}
                    onClick={() => handleSelect(project.id)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-sm px-2 py-2 text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer transition-colors",
                      value === project.id && "bg-accent"
                    )}
                  >
                    <Check
                      className={cn(
                        "h-4 w-4 shrink-0",
                        value === project.id ? "opacity-100" : "opacity-0"
                      )}
                    />
                    <Folder className="h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="truncate flex-1 text-left">{project.name}</span>
                  </button>
                ))}
                {projectsData && projectsData.total > projects.length && (
                  <div className="px-2 py-2 text-xs text-muted-foreground text-center border-t mt-1">
                    Showing {projects.length} of {projectsData.total} projects. Type to search for more.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
