import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  getProjectPolicy, putProjectPolicy, deleteProjectPolicy, getEffectivePolicy,
} from "@/api/cryptoPolicy";
import { CryptoPolicyEditor } from "@/components/crypto/CryptoPolicyEditor";
import type { CryptoRule } from "@/types/cryptoPolicy";

interface Props {
  projectId: string;
  canEdit: boolean;
}

export function CryptoPolicyOverridePage({ projectId, canEdit }: Props) {
  const qc = useQueryClient();
  const effective = useQuery({
    queryKey: ["crypto-policy-effective", projectId],
    queryFn: () => getEffectivePolicy(projectId),
  });
  const override = useQuery({
    queryKey: ["crypto-policy-override", projectId],
    queryFn: () => getProjectPolicy(projectId),
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

  if (effective.isLoading || override.isLoading || !effective.data || !override.data) {
    return <div>Loading…</div>;
  }

  return (
    <div className="space-y-6 p-6">
      <div className="rounded border bg-muted/20 p-3 text-sm">
        Effective policy: system version {effective.data.system_version}
        {effective.data.override_version
          ? ` + override version ${effective.data.override_version}`
          : " (no override active)"}
      </div>
      <CryptoPolicyEditor
        title="Project override"
        subtitle="Rules added or edited here apply on top of the system policy for this project only."
        initialRules={override.data.rules}
        readOnly={!canEdit}
        onSave={async (rules) => { await save.mutateAsync(rules); }}
        onResetOverride={
          canEdit && override.data.rules.length > 0
            ? async () => { await reset.mutateAsync(); }
            : undefined
        }
      />
    </div>
  );
}
