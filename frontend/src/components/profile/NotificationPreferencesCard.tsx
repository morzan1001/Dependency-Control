import { useState } from 'react';
import { useUpdateMe } from '@/hooks/queries/use-users';
import { User } from '@/types/user';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

const NOTIFICATION_EVENTS = [
  { id: 'analysis_completed', label: 'Analysis Completed', description: 'When a dependency scan finishes.' },
  { id: 'vulnerability_found', label: 'Vulnerability Found', description: 'When critical/high vulnerabilities are detected.' },
] as const;

const NOTIFICATION_CHANNELS = [
  { id: 'email', label: 'Email' },
  { id: 'slack', label: 'Slack' },
  { id: 'mattermost', label: 'Mattermost' },
] as const;

interface NotificationPreferencesCardProps {
  user: User | undefined;
  availableChannels: string[] | undefined;
}

export function NotificationPreferencesCard({ user, availableChannels }: NotificationPreferencesCardProps) {
  const [prefs, setPrefs] = useState<Record<string, string[]>>(
    () => user?.notification_preferences || {}
  );

  const updateMeMutation = useUpdateMe();

  const toggleChannel = (event: string, channel: string) => {
    setPrefs(prev => {
      const currentChannels = prev[event] || [];
      const newChannels = currentChannels.includes(channel)
        ? currentChannels.filter(c => c !== channel)
        : [...currentChannels, channel];

      const updated = { ...prev };
      if (newChannels.length > 0) {
        updated[event] = newChannels;
      } else {
        delete updated[event];
      }
      return updated;
    });
  };

  const handleSave = () => {
    updateMeMutation.mutate(
      { notification_preferences: prefs },
      {
        onSuccess: () => toast.success("Notification preferences saved"),
        onError: (error) => toast.error("Failed to save preferences", {
          description: getErrorMessage(error),
        }),
      }
    );
  };

  const channels = NOTIFICATION_CHANNELS.filter(c => availableChannels?.includes(c.id));

  if (channels.length === 0) {
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
        <div className="border rounded-md">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[250px]">Event</TableHead>
                {channels.map(channel => (
                  <TableHead key={channel.id} className="text-center capitalize">{channel.label}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {NOTIFICATION_EVENTS.map(event => (
                <TableRow key={event.id}>
                  <TableCell>
                    <div className="font-medium">{event.label}</div>
                    <div className="text-xs text-muted-foreground">{event.description}</div>
                  </TableCell>
                  {channels.map(channel => (
                    <TableCell key={channel.id} className="text-center">
                      <div className="flex justify-center">
                        <Checkbox
                          id={`global-${event.id}-${channel.id}`}
                          checked={(prefs[event.id] || []).includes(channel.id)}
                          onCheckedChange={() => toggleChannel(event.id, channel.id)}
                        />
                      </div>
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <Button onClick={handleSave} disabled={updateMeMutation.isPending}>
          {updateMeMutation.isPending ? "Saving..." : "Save Preferences"}
        </Button>
      </CardContent>
    </Card>
  );
}
