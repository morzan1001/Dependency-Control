import { api } from "@/api/client";
import type {
  CryptoPolicyDoc,
  CryptoRule,
  EffectivePolicy,
} from "@/types/cryptoPolicy";

export async function getSystemPolicy(): Promise<CryptoPolicyDoc> {
  const { data } = await api.get<CryptoPolicyDoc>("/crypto-policies/system");
  return data;
}

export async function putSystemPolicy(rules: CryptoRule[]): Promise<CryptoPolicyDoc> {
  const { data } = await api.put<CryptoPolicyDoc>(
    "/crypto-policies/system",
    { rules }
  );
  return data;
}

export async function getProjectPolicy(projectId: string): Promise<CryptoPolicyDoc> {
  const { data } = await api.get<CryptoPolicyDoc>(
    `/projects/${projectId}/crypto-policy`
  );
  return data;
}

export async function putProjectPolicy(
  projectId: string, rules: CryptoRule[]
): Promise<CryptoPolicyDoc> {
  const { data } = await api.put<CryptoPolicyDoc>(
    `/projects/${projectId}/crypto-policy`,
    { rules }
  );
  return data;
}

export async function deleteProjectPolicy(projectId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/crypto-policy`);
}

export async function getEffectivePolicy(projectId: string): Promise<EffectivePolicy> {
  const { data } = await api.get<EffectivePolicy>(
    `/projects/${projectId}/crypto-policy/effective`
  );
  return data;
}
