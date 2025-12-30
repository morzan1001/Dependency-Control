import type { Finding } from '@/lib/api'

export const getFindingTitle = (finding: Finding) => finding.id || 'Finding Details'
export const getFindingPackage = (finding: Finding) => finding.component || 'Unknown'
export const getFindingVersion = (finding: Finding) => finding.version || 'Unknown'
export const getFindingId = (finding: Finding) => finding.id
