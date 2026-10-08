import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Plus } from 'lucide-react'
import { WaiverList } from '@/components/waivers/WaiverList'
import { CreateGlobalWaiverDialog } from '@/components/waivers/CreateGlobalWaiverDialog'

export default function GlobalWaivers() {
    const [createDialogOpen, setCreateDialogOpen] = useState(false)

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:justify-between sm:items-start">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Global Waivers</h1>
                    <p className="text-muted-foreground">
                        Manage waivers that apply across all projects. Global waivers are applied during every scan.
                    </p>
                </div>
                <Button onClick={() => setCreateDialogOpen(true)}>
                    <Plus className="h-4 w-4 mr-2" />
                    Create Global Waiver
                </Button>
            </div>

            <WaiverList />

            <CreateGlobalWaiverDialog
                open={createDialogOpen}
                onOpenChange={setCreateDialogOpen}
            />
        </div>
    )
}
