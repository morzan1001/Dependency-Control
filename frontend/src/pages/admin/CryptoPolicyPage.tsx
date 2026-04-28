import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { getSystemPolicy, putSystemPolicy } from "@/api/cryptoPolicy";
import { CryptoPolicyEditor } from "@/components/crypto/CryptoPolicyEditor";
import { PolicyAuditTimeline } from "@/components/audit/PolicyAuditTimeline";
import type { CryptoRule } from "@/types/cryptoPolicy";

export function CryptoPolicyPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["crypto-policy-system"],
    queryFn: getSystemPolicy,
  });

  const save = useMutation({
    mutationFn: (rules: CryptoRule[]) => putSystemPolicy(rules),
    onSuccess: () => {
      toast.success("System policy saved");
      qc.invalidateQueries({ queryKey: ["crypto-policy-system"] });
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  if (isLoading || !data) return <div>Loading…</div>;

  return (
    <div className="space-y-6 p-6">
      <CryptoPolicyEditor
        title="System Crypto Policy"
        subtitle={`Version ${data.version}${data.updated_by ? ` · last edited by ${data.updated_by}` : ""}`}
        initialRules={data.rules}
        onSave={async (rules) => { await save.mutateAsync(rules); }}
      />
      <PolicyAuditTimeline policyScope="system" canRevert={true} />
    </div>
  );
}

export default CryptoPolicyPage;
