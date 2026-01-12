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

export default function SystemSettings() {
  const queryClient = useQueryClient()
  const { hasPermission } = useAuth()
  const [formData, setFormData] = useState<Partial<SystemSettingsType>>({})
  const [slackAuthMode, setSlackAuthMode] = useState("oauth")
  const [searchParams, setSearchParams] = useSearchParams()

  const { data: settings, isLoading } = useSystemSettings();

  useEffect(() => {
    if (settings) {
      setFormData(settings)
      if (settings.slack_bot_token && !settings.slack_client_id) {
        setSlackAuthMode("manual")
      }
    }
  }, [settings])

  useEffect(() => {
    if (searchParams.get('slack_connected') === 'true') {
      toast.success("Slack connected successfully!", {
        description: "Your Slack workspace has been linked."
      })
      // Remove the query param
      setSearchParams(params => {
        params.delete('slack_connected')
        return params
      })
      // Refresh settings to show the new token status
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] })
    }
  }, [searchParams, setSearchParams, queryClient])

  const mutation = useUpdateSystemSettings();

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

  if (isLoading) {
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
