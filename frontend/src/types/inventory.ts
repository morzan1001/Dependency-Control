import type { PaginatedResponse } from './common';

export interface InventoryScanContext {
  scan_id: string;
  branch: string;
  created_at: string;
  commit_hash?: string | null;
}

export interface InventoryStats {
  scan: InventoryScanContext;
  components_total: number;
  direct_count: number;
  transitive_count: number;
  license_count: number;
  ecosystem_count: number;
  ecosystems: string[];
  crypto_asset_count: number;
  cbom_evaluated: boolean;
}

export interface ComponentItem {
  name: string;
  version: string;
  latest_version?: string | null;
  ecosystem: string;
  license?: string | null;
  license_category?: string | null;
  direct: boolean;
  eol: boolean;
  outdated: boolean;
  purl?: string | null;
}

export interface ComponentsPage extends PaginatedResponse<ComponentItem> {
  scan: InventoryScanContext;
  page_size: number;
}

export interface LicenseItem {
  license: string;
  category?: string | null;
  risks: string[];
  component_count: number;
  components: string[];
}

export interface LicensesPayload {
  scan: InventoryScanContext;
  items: LicenseItem[];
}

export interface CryptoItem {
  name: string;
  asset_type: string;
  primitive?: string | null;
  variant?: string | null;
  key_size_bits?: number | null;
  location_count: number;
  locations: string[];
}

export interface CryptoPage extends PaginatedResponse<CryptoItem> {
  scan: InventoryScanContext;
  page_size: number;
}

export type InventoryTable = 'components' | 'licenses' | 'crypto';
