import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Info, Lock } from "lucide-react";
import {
  putProjectPolicy, deleteProjectPolicy, getEffectivePolicy,
} from "@/api/cryptoPolicy";
import { CryptoPolicyEditor } from "@/components/crypto/CryptoPolicyEditor";
import { PolicyAuditTimeline } from "@/components/audit/PolicyAuditTimeline";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { CryptoRule } from "@/types/cryptoPolicy";

interface Props {
  readonly projectId: string;
  readonly canEdit: boolean;
}

export function CryptoPolicyOverridePage({ projectId, canEdit }: Props) {
  const qc = useQueryClient();
  const effective = useQuery({
    queryKey: ["crypto-policy-effective", projectId],
    queryFn: () => getEffectivePolicy(projectId),
  });

  const save = useMutation({
    mutationFn: (rules: CryptoRule[]) => putProjectPolicy(projectId, rules),
    onSuccess: () => {
      toast.success("Override saved");
      qc.invalidateQueries({ queryKey: ["crypto-policy-effective", projectId] });
      qc.invalidateQueries({ queryKey: ["crypto-policy-override", projectId] });
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  const reset = useMutation({
    mutationFn: () => deleteProjectPolicy(projectId),
    onSuccess: () => {
      toast.success("Override removed");
      qc.invalidateQueries({ queryKey: ["crypto-policy-effective", projectId] });
      qc.invalidateQueries({ queryKey: ["crypto-policy-override", projectId] });
    },
  });

  if (effective.isLoading) return <div>Loading…</div>;
  if (effective.isError || !effective.data) {
    return <div className="p-6 text-destructive">Failed to load crypto policy.</div>;
  }

  const lockedByAdmin = effective.data.override_locked;
  const editable = canEdit && !lockedByAdmin;
  const hasOverride = (effective.data.override_version ?? 0) > 0;

  let overrideStatus: string;
  if (!effective.data.override_version) {
    overrideStatus = "no override active";
  } else if (lockedByAdmin) {
    overrideStatus = `override version ${effective.data.override_version} stored but ignored`;
  } else {
    overrideStatus = `override version ${effective.data.override_version}`;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cryptographic Policy</CardTitle>
        <CardDescription>
          System version {effective.data.system_version} · {overrideStatus} · {effective.data.rules.length}{" "}
          rule{effective.data.rules.length === 1 ? "" : "s"} applied
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {lockedByAdmin && (
          <div className="flex items-start gap-2 p-4 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900">
            <Lock className="h-4 w-4 mt-0.5 shrink-0" />
            <p>
              An administrator has enforced the system crypto policy globally.
              Project overrides are read-only and not applied during scans.
              Saved override rules are kept on disk and re-apply automatically if the global enforcement is later disabled.
            </p>
          </div>
        )}

        <CryptoPolicyEditor
          subtitle="Every rule that applies when scanning this project. Edit a system rule to override it; revert or remove to drop the override."
          initialRules={effective.data.rules}
          systemRules={effective.data.system_rules}
          readOnly={!editable}
          onSave={async (rules) => { await save.mutateAsync(rules); }}
          onResetOverride={
            editable && hasOverride
              ? async () => { await reset.mutateAsync(); }
              : undefined
          }
        />

        {!canEdit && !lockedByAdmin && (
          <div className="flex items-center gap-2 p-3 text-sm text-blue-800 bg-blue-50 border border-blue-200 rounded-lg dark:bg-blue-950/50 dark:text-blue-200 dark:border-blue-900">
            <Info className="h-4 w-4 shrink-0" />
            <p>You need project admin rights to edit overrides.</p>
          </div>
        )}

        <PolicyAuditTimeline
          policyScope="project"
          projectId={projectId}
          canRevert={editable}
        />
      </CardContent>
    </Card>
  );
}
