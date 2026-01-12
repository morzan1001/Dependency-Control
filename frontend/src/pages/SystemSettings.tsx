import { useEffect, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { useQueryClient } from "@tanstack/react-query"
import { useSystemSettings, useUpdateSystemSettings } from "@/hooks/queries/use-system"
import { useGlobalWebhooks, useCreateGlobalWebhook, useDeleteWebhook } from "@/hooks/queries/use-webhooks"
import { SystemSettings as SystemSettingsType } from "@/types/system"
import { useAuth } from "@/context/useAuth"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { toast } from "sonner"
import { Skeleton } from "@/components/ui/skeleton"
import {
  GeneralSettingsTab,
  SecuritySettingsTab,
  NotificationsSettingsTab,
  IntegrationsSettingsTab,
} from "@/components/settings"

// Inner component that handles the form state
function SystemSettingsForm({ settings }: { settings: SystemSettingsType }) {
  const [formData, setFormData] = useState<Partial<SystemSettingsType>>(settings)
  const [slackAuthMode, setSlackAuthMode] = useState(() => {
    if (settings.slack_bot_token && !settings.slack_client_id) {
       return "manual"
    }
    return "oauth"
  })
  
  const { hasPermission } = useAuth()
  const mutation = useUpdateSystemSettings();
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  useEffect(() => {
    if (searchParams.get('slack_connected') === 'true') {
      toast.success("Slack connected successfully!", {
        description: "Your Slack workspace has been linked."
      })
      setSearchParams(params => {
        params.delete('slack_connected')
        return params
      })
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] })
    }
  }, [searchParams, setSearchParams, queryClient])

  const handleInputChange = (field: keyof SystemSettingsType, value: string | number | boolean) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const handleSave = () => {
    mutation.mutate(formData, {
      onSuccess: () => toast.success("Settings updated successfully"),
      onError: () => toast.error("Failed to update settings")
    })
  }

  const { data: webhooks, isLoading: isLoadingWebhooks } = useGlobalWebhooks();

  const createWebhookMutation = useCreateGlobalWebhook();
  const deleteWebhookMutation = useDeleteWebhook();

  const tabProps = {
    formData,
    handleInputChange,
    handleSave,
    hasPermission,
    isPending: mutation.isPending,
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">System Settings</h2>
        <p className="text-muted-foreground">
          Manage global system configurations and preferences.
        </p>
      </div>

      <Tabs defaultValue="general" className="space-y-4">
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="integrations">Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="general">
          <GeneralSettingsTab {...tabProps} />
        </TabsContent>

        <TabsContent value="security">
          <SecuritySettingsTab {...tabProps} />
        </TabsContent>

        <TabsContent value="notifications">
          <NotificationsSettingsTab
            {...tabProps}
            slackAuthMode={slackAuthMode}
            setSlackAuthMode={setSlackAuthMode}
            settings={settings}
            webhooks={webhooks || []}
            isLoadingWebhooks={isLoadingWebhooks}
            onCreateWebhook={(data) => createWebhookMutation.mutateAsync(data)}
            onDeleteWebhook={(id) => deleteWebhookMutation.mutateAsync(id)}
          />
        </TabsContent>
        
        <TabsContent value="integrations">
          <IntegrationsSettingsTab {...tabProps} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

export default function SystemSettings() {
  const { data: settings, isLoading } = useSystemSettings();

  if (isLoading || !settings) {
    return (
      <div className="space-y-6">
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Skeleton className="h-[500px] w-full" />
      </div>
    )
  }

  return <SystemSettingsForm settings={settings} />
}
