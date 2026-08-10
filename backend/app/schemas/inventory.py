"""Response envelopes for the per-project inventory endpoints."""

from datetime import datetime

from pydantic import BaseModel, Field


class InventoryScanContext(BaseModel):
    scan_id: str
    branch: str
    created_at: datetime
    commit_hash: str | None = None


class InventoryStatsResponse(BaseModel):
    scan: InventoryScanContext
    components_total: int
    direct_count: int
    transitive_count: int
    license_count: int
    ecosystem_count: int
    crypto_asset_count: int


class ComponentItem(BaseModel):
    name: str
    version: str
    latest_version: str | None = None
    ecosystem: str = "unknown"
    license: str | None = None
    license_category: str | None = None
    direct: bool = False
    eol: bool = False
    outdated: bool = False
    purl: str | None = None


class ComponentsPageResponse(BaseModel):
    scan: InventoryScanContext
    items: list[ComponentItem]
    total: int
    page: int
    page_size: int


class LicenseItem(BaseModel):
    license: str
    category: str | None = None
    risks: list[str] = Field(default_factory=list)
    component_count: int
    components: list[str] = Field(default_factory=list)


class LicensesResponse(BaseModel):
    scan: InventoryScanContext
    items: list[LicenseItem]


class CryptoItem(BaseModel):
    name: str
    asset_type: str
    primitive: str | None = None
    variant: str | None = None
    key_size_bits: int | None = None
    location_count: int = 0
    locations: list[str] = Field(default_factory=list)


class CryptoPageResponse(BaseModel):
    scan: InventoryScanContext
    items: list[CryptoItem]
    total: int
    page: int
    page_size: int
