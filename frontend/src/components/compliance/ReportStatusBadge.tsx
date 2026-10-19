import type { ComponentProps } from "react";
import { StatusPill } from "@/components/users/UserStatusBadge";
import type { ReportStatus } from "@/types/compliance";

const TONE: Record<ReportStatus, ComponentProps<typeof StatusPill>["tone"]> = {
  pending: "yellow",
  generating: "yellow",
  completed: "green",
  failed: "red",
};

const LABEL: Record<ReportStatus, string> = {
  pending: "Pending",
  generating: "Generating…",
  completed: "Completed",
  failed: "Failed",
};

export function ReportStatusBadge({ status }: Readonly<{ status: ReportStatus }>) {
  return <StatusPill tone={TONE[status]}>{LABEL[status]}</StatusPill>;
}
