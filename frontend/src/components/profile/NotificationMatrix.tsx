import { Checkbox } from '@/components/ui/checkbox'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { NOTIFICATION_CHANNELS, NOTIFICATION_EVENTS } from '@/lib/constants'
import { toggle } from '@/lib/utils'

interface NotificationMatrixProps {
  value: Record<string, string[]>
  onChange: (value: Record<string, string[]>) => void
  channels: readonly string[] | undefined
  disabled?: boolean
}

export function NotificationMatrix({ value, onChange, channels, disabled }: Readonly<NotificationMatrixProps>) {
  const columns = NOTIFICATION_CHANNELS.filter((channel) => channels?.includes(channel.id))

  const toggleChannel = (event: string, channel: string) => {
    const next = toggle(value[event] ?? [], channel)
    const updated = { ...value, [event]: next }
    if (next.length === 0) delete updated[event]
    onChange(updated)
  }

  return (
    <div className="border rounded-md">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[300px]">Event</TableHead>
            {columns.map((channel) => (
              <TableHead key={channel.id} className="text-center">{channel.label}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {NOTIFICATION_EVENTS.map((event) => (
            <TableRow key={event.id} className={disabled ? 'opacity-60' : undefined}>
              <TableCell>
                <div className="font-medium">{event.label}</div>
                <div className="text-xs text-muted-foreground">{event.description}</div>
              </TableCell>
              {columns.map((channel) => (
                <TableCell key={channel.id} className="text-center">
                  <div className="flex justify-center">
                    <Checkbox
                      aria-label={`${event.label}: ${channel.label}`}
                      checked={(value[event.id] ?? []).includes(channel.id)}
                      onCheckedChange={() => toggleChannel(event.id, channel.id)}
                      disabled={disabled}
                    />
                  </div>
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
