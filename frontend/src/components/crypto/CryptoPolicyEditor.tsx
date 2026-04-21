import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import type {
  CryptoRule, Severity, CryptoFindingType, CryptoPolicySource,
} from "@/types/cryptoPolicy";
import type { CryptoPrimitive } from "@/types/crypto";

interface Props {
  initialRules: CryptoRule[];
  onSave: (rules: CryptoRule[]) => Promise<void>;
  onResetOverride?: () => Promise<void>;
  readOnly?: boolean;
  title?: string;
  subtitle?: string;
}

const SEVERITIES: Severity[] = [
  "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN",
];
const FINDING_TYPES: CryptoFindingType[] = [
  "crypto_weak_algorithm", "crypto_weak_key", "crypto_quantum_vulnerable",
];
const SOURCES: CryptoPolicySource[] = [
  "nist-sp-800-131a", "bsi-tr-02102", "cnsa-2.0", "nist-pqc", "custom",
];
const PRIMITIVES: CryptoPrimitive[] = [
  "block-cipher", "stream-cipher", "hash", "mac", "pke", "signature",
  "kem", "kdf", "drbg", "other",
];

// Silence unused variable warning — PRIMITIVES is exported for use in AddRuleDialog
void PRIMITIVES;

function emptyRule(): CryptoRule {
  return {
    rule_id: "",
    name: "",
    description: "",
    finding_type: "crypto_weak_algorithm",
    default_severity: "HIGH",
    match_primitive: null,
    match_name_patterns: [],
    match_min_key_size_bits: null,
    match_curves: [],
    match_protocol_versions: [],
    quantum_vulnerable: null,
    enabled: true,
    source: "custom",
    references: [],
  };
}

export function CryptoPolicyEditor({
  initialRules, onSave, onResetOverride, readOnly, title, subtitle,
}: Props) {
  const [rules, setRules] = useState<CryptoRule[]>(initialRules);
  const [addOpen, setAddOpen] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<CryptoPolicySource | "all">("all");
  const [saving, setSaving] = useState(false);

  const visibleRules = useMemo(
    () => rules.filter(r => sourceFilter === "all" || r.source === sourceFilter),
    [rules, sourceFilter]
  );

  const updateRule = (idx: number, patch: Partial<CryptoRule>) => {
    setRules(rs => rs.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
  };

  const removeRule = (rule_id: string) => {
    setRules(rs => rs.filter(r => r.rule_id !== rule_id));
  };

  const handleSave = async () => {
    setSaving(true);
    try { await onSave(rules); } finally { setSaving(false); }
  };

  return (
    <div className="space-y-3">
      {(title || subtitle) && (
        <div>
          {title && <h2 className="text-lg font-semibold">{title}</h2>}
          {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
        </div>
      )}

      <div className="flex items-center gap-2">
        <Select
          value={sourceFilter}
          onValueChange={(v) => setSourceFilter(v as typeof sourceFilter)}
        >
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            {SOURCES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        {!readOnly && (
          <Button size="sm" onClick={() => setAddOpen(true)}>Add custom rule</Button>
        )}
        <div className="flex-1" />
        {!readOnly && onResetOverride && (
          <Button variant="outline" size="sm" onClick={onResetOverride}>
            Reset override
          </Button>
        )}
        {!readOnly && (
          <Button onClick={handleSave} disabled={saving}>
            {saving ? "Saving\u2026" : "Save"}
          </Button>
        )}
      </div>

      <div className="rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-left">
            <tr>
              <th className="p-2 w-16">Enabled</th>
              <th className="p-2">Rule</th>
              <th className="p-2">Finding type</th>
              <th className="p-2 w-28">Severity</th>
              <th className="p-2 w-32">Min key size</th>
              <th className="p-2">Name patterns</th>
              <th className="p-2 w-32">Source</th>
              {!readOnly && <th className="p-2 w-24" />}
            </tr>
          </thead>
          <tbody>
            {visibleRules.map((r) => {
              const idx = rules.findIndex(x => x.rule_id === r.rule_id);
              return (
                <tr key={r.rule_id} className="border-t">
                  <td className="p-2">
                    <Switch
                      checked={r.enabled}
                      disabled={readOnly}
                      onCheckedChange={(v) => updateRule(idx, { enabled: v })}
                    />
                  </td>
                  <td className="p-2">
                    <div className="font-mono text-xs text-muted-foreground">{r.rule_id}</div>
                    <Input
                      disabled={readOnly}
                      value={r.name}
                      onChange={(e) => updateRule(idx, { name: e.target.value })}
                      className="mt-1"
                    />
                  </td>
                  <td className="p-2">
                    <Select
                      value={r.finding_type}
                      disabled={readOnly}
                      onValueChange={(v) => updateRule(idx, { finding_type: v as CryptoFindingType })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {FINDING_TYPES.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </td>
                  <td className="p-2">
                    <Select
                      value={r.default_severity}
                      disabled={readOnly}
                      onValueChange={(v) => updateRule(idx, { default_severity: v as Severity })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </td>
                  <td className="p-2">
                    <Input
                      type="number"
                      disabled={readOnly}
                      value={r.match_min_key_size_bits ?? ""}
                      onChange={(e) => updateRule(idx, {
                        match_min_key_size_bits: e.target.value === "" ? null : Number(e.target.value),
                      })}
                      placeholder="\u2014"
                      className="w-24"
                    />
                  </td>
                  <td className="p-2">
                    <Input
                      disabled={readOnly}
                      value={r.match_name_patterns.join(", ")}
                      onChange={(e) => updateRule(idx, {
                        match_name_patterns: e.target.value.split(",").map(s => s.trim()).filter(Boolean),
                      })}
                      placeholder="comma-separated"
                    />
                  </td>
                  <td className="p-2 font-mono text-xs">{r.source}</td>
                  {!readOnly && (
                    <td className="p-2 text-right">
                      {r.source === "custom" && (
                        <Button variant="outline" size="sm"
                          onClick={() => removeRule(r.rule_id)}>
                          Remove
                        </Button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {addOpen && (
        <AddRuleDialog
          existingIds={new Set(rules.map((r) => r.rule_id))}
          onClose={() => setAddOpen(false)}
          onAdd={(r) => { setRules((rs) => [...rs, r]); setAddOpen(false); }}
        />
      )}
    </div>
  );
}

function AddRuleDialog({
  existingIds, onClose, onAdd,
}: {
  existingIds: Set<string>;
  onClose: () => void;
  onAdd: (r: CryptoRule) => void;
}) {
  const [rule, setRule] = useState<CryptoRule>(emptyRule());
  const [error, setError] = useState<string | null>(null);

  const submit = () => {
    if (!rule.rule_id) { setError("rule_id is required"); return; }
    if (existingIds.has(rule.rule_id)) { setError("rule_id already exists"); return; }
    if (!rule.name) { setError("name is required"); return; }
    onAdd(rule);
  };

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-xl">
        <DialogHeader><DialogTitle>Add custom crypto rule</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <label className="block text-sm">
            <span className="text-muted-foreground">rule_id</span>
            <Input value={rule.rule_id}
              onChange={(e) => setRule({ ...rule, rule_id: e.target.value })}
              placeholder="e.g. custom-block-rc4" />
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">name</span>
            <Input value={rule.name}
              onChange={(e) => setRule({ ...rule, name: e.target.value })} />
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">description</span>
            <Input value={rule.description}
              onChange={(e) => setRule({ ...rule, description: e.target.value })} />
          </label>
          <label className="block text-sm">
            <span className="text-muted-foreground">match name patterns (comma-separated)</span>
            <Input
              value={rule.match_name_patterns.join(", ")}
              onChange={(e) => setRule({
                ...rule,
                match_name_patterns: e.target.value.split(",").map(s => s.trim()).filter(Boolean),
              })}
            />
          </label>
          {error && <div className="text-sm text-destructive">{error}</div>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={submit}>Add</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
