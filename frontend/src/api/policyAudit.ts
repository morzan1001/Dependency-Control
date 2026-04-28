import { api } from "@/api/client";
import type { PolicyAuditEntry, PolicyAuditListResponse } from "@/types/policyAudit";

export interface ListAuditParams {
  skip?: number;
  limit?: number;
}

export async function listSystemAudit(p: ListAuditParams = {}): Promise<PolicyAuditListResponse> {
  const { data } = await api.get<PolicyAuditListResponse>(
    "/crypto-policies/system/audit",
    { params: p },
  );
  return data;
}

export async function getSystemAuditEntry(version: number): Promise<PolicyAuditEntry> {
  const { data } = await api.get<PolicyAuditEntry>(
    `/crypto-policies/system/audit/${version}`,
  );
  return data;
}

export async function revertSystemPolicy(
  target_version: number, comment?: string,
): Promise<void> {
  await api.post("/crypto-policies/system/revert", { target_version, comment });
}

export async function pruneSystemAudit(before: string): Promise<{ deleted: number }> {
  const { data } = await api.delete<{ deleted: number }>(
    `/crypto-policies/system/audit`,
    { params: { before } },
  );
  return data;
}

export async function listProjectAudit(
  project_id: string, p: ListAuditParams = {},
): Promise<PolicyAuditListResponse> {
  const { data } = await api.get<PolicyAuditListResponse>(
    `/projects/${project_id}/crypto-policy/audit`,
    { params: p },
  );
  return data;
}

export async function getProjectAuditEntry(
  project_id: string, version: number,
): Promise<PolicyAuditEntry> {
  const { data } = await api.get<PolicyAuditEntry>(
    `/projects/${project_id}/crypto-policy/audit/${version}`,
  );
  return data;
}

export async function revertProjectPolicy(
  project_id: string, target_version: number, comment?: string,
): Promise<void> {
  await api.post(`/projects/${project_id}/crypto-policy/revert`, {
    target_version, comment,
  });
}

export async function pruneProjectAudit(
  project_id: string, before: string,
): Promise<{ deleted: number }> {
  const { data } = await api.delete<{ deleted: number }>(
    `/projects/${project_id}/crypto-policy/audit`,
    { params: { before } },
  );
  return data;
}
