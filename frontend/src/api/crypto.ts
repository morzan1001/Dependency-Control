import { api } from "@/api/client";
import type {
  CryptoAsset,
  CryptoAssetListResponse,
  CryptoAssetSummary,
  CryptoAssetType,
  CryptoPrimitive,
} from "@/types/crypto";

export interface ListCryptoAssetsParams {
  projectId: string;
  scanId: string;
  assetType?: CryptoAssetType;
  primitive?: CryptoPrimitive;
  nameSearch?: string;
  skip?: number;
  limit?: number;
}

export async function listCryptoAssets(p: ListCryptoAssetsParams): Promise<CryptoAssetListResponse> {
  const { data } = await api.get<CryptoAssetListResponse>(
    `/projects/${p.projectId}/crypto-assets`,
    {
      params: {
        scan_id: p.scanId,
        asset_type: p.assetType,
        primitive: p.primitive,
        name_search: p.nameSearch,
        skip: p.skip ?? 0,
        limit: p.limit ?? 100,
      },
    }
  );
  return data;
}

export async function getCryptoAsset(projectId: string, assetId: string): Promise<CryptoAsset> {
  const { data } = await api.get<CryptoAsset>(
    `/projects/${projectId}/crypto-assets/${assetId}`
  );
  return data;
}

export async function getCryptoSummary(projectId: string, scanId: string): Promise<CryptoAssetSummary> {
  const { data } = await api.get<CryptoAssetSummary>(
    `/projects/${projectId}/scans/${scanId}/crypto-assets/summary`
  );
  return data;
}
