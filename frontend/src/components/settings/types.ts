import { SystemSettings as SystemSettingsType } from "@/types/system"

export interface SettingsTabProps {
  formData: Partial<SystemSettingsType>
  handleInputChange: (field: keyof SystemSettingsType, value: string | number | boolean) => void
  handleSave: () => void
  hasPermission: (permission: string) => boolean
  isPending: boolean
}
