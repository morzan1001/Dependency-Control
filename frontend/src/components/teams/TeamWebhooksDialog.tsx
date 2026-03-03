import { useTeamWebhooks, useCreateTeamWebhook, useDeleteWebhook } from '@/hooks/queries/use-webhooks';
import { WebhookManager } from '@/components/WebhookManager';
import { WebhookCreate } from '@/types/webhook';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"

interface TeamWebhooksDialogProps {
  teamId: string | null;
  teamName: string;
  isOpen: boolean;
  onClose: () => void;
  canCreate: boolean;
  canDelete: boolean;
}

export function TeamWebhooksDialog({ teamId, teamName, isOpen, onClose, canCreate, canDelete }: TeamWebhooksDialogProps) {
  const { data: webhooks, isLoading } = useTeamWebhooks(teamId || '');
  const createMutation = useCreateTeamWebhook();
  const deleteMutation = useDeleteWebhook();

  const handleCreate = async (data: WebhookCreate) => {
    if (!teamId) return {} as any;
    return createMutation.mutateAsync({ teamId, data });
  };

  const handleDelete = async (id: string) => {
    await deleteMutation.mutateAsync(id);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>Team Webhooks - {teamName}</DialogTitle>
          <DialogDescription>
            Webhooks that receive notifications for all projects in this team.
          </DialogDescription>
        </DialogHeader>
        <div className="py-4">
          <WebhookManager
            webhooks={webhooks || []}
            isLoading={isLoading}
            onCreate={handleCreate}
            onDelete={handleDelete}
            title="Webhooks"
            description="Manage webhooks for this team. These webhooks will be triggered for all projects belonging to this team."
            createPermission={canCreate}
            deletePermission={canDelete}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
