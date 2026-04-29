import { api } from "@/api/client";
import type { MigrationPlanResponse } from "@/types/pqcMigration";

export interface GetPQCPlanParams {
  scope: "project" | "team" | "global" | "user";
  scope_id?: string;
  limit?: number;
}

export async function getPQCMigrationPlan(
  p: GetPQCPlanParams,
): Promise<MigrationPlanResponse> {
  const { data } = await api.get<MigrationPlanResponse>(
    "/analytics/crypto/pqc-migration",
    { params: p },
  );
  return data;
}
