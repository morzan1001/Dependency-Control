import { useState } from 'react';
import { useUpdateMe } from '@/hooks/queries/use-users';
import { User } from '@/types/user';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { toast } from "sonner"
import { NotificationMatrix } from './NotificationMatrix';

interface NotificationPreferencesCardProps {
  readonly user: User | undefined;
  readonly availableChannels: string[] | undefined;
}

export function NotificationPreferencesCard({ user, availableChannels }: NotificationPreferencesCardProps) {
  const [prefs, setPrefs] = useState<Record<string, string[]>>(
    () => user?.notification_preferences || {}
  );

  const updateMeMutation = useUpdateMe({ errorTitle: "Failed to save preferences" });

  const handleSave = () => {
    updateMeMutation.mutate(
      { notification_preferences: prefs },
      { onSuccess: () => toast.success("Notification preferences saved") }
    );
  };

  if (!availableChannels?.length) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Notification Preferences</CardTitle>
        <CardDescription>
          Choose how you want to be notified about project events. These are your default preferences and can be overridden per project.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <NotificationMatrix value={prefs} onChange={setPrefs} channels={availableChannels} />
        <Button onClick={handleSave} disabled={updateMeMutation.isPending}>
          {updateMeMutation.isPending ? "Saving..." : "Save Preferences"}
        </Button>
      </CardContent>
    </Card>
  );
}
