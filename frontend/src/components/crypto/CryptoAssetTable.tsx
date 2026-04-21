import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listCryptoAssets } from "@/api/crypto";
import type { CryptoAsset, CryptoAssetType, CryptoPrimitive } from "@/types/crypto";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

const ASSET_TYPES: { value: CryptoAssetType; label: string }[] = [
  { value: "algorithm", label: "Algorithm" },
  { value: "certificate", label: "Certificate" },
  { value: "protocol", label: "Protocol" },
  { value: "related-crypto-material", label: "Key Material" },
];

const PRIMITIVES: { value: CryptoPrimitive; label: string }[] = [
  { value: "block-cipher", label: "Block Cipher" },
  { value: "stream-cipher", label: "Stream Cipher" },
  { value: "hash", label: "Hash" },
  { value: "mac", label: "MAC" },
  { value: "pke", label: "PKE" },
  { value: "signature", label: "Signature" },
  { value: "kem", label: "KEM" },
  { value: "kdf", label: "KDF" },
  { value: "drbg", label: "DRBG" },
  { value: "other", label: "Other" },
];

const PAGE_SIZE = 50;

interface Props {
  projectId: string;
  scanId: string;
  onSelect: (asset: CryptoAsset) => void;
}

export function CryptoAssetTable({ projectId, scanId, onSelect }: Props) {
  const [assetType, setAssetType] = useState<CryptoAssetType | undefined>();
  const [primitive, setPrimitive] = useState<CryptoPrimitive | undefined>();
  const [nameSearch, setNameSearch] = useState("");
  const [skip, setSkip] = useState(0);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["crypto-assets", projectId, scanId, assetType, primitive, nameSearch, skip],
    queryFn: () =>
      listCryptoAssets({
        projectId,
        scanId,
        assetType,
        primitive,
        nameSearch: nameSearch || undefined,
        skip,
        limit: PAGE_SIZE,
      }),
    enabled: !!projectId && !!scanId,
  });

  const handleAssetTypeChange = (value: string) => {
    setAssetType(value === "all" ? undefined : (value as CryptoAssetType));
    setSkip(0);
  };

  const handlePrimitiveChange = (value: string) => {
    setPrimitive(value === "all" ? undefined : (value as CryptoPrimitive));
    setSkip(0);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setNameSearch(e.target.value);
    setSkip(0);
  };

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;
  const currentPage = Math.floor(skip / PAGE_SIZE) + 1;

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <Input
          placeholder="Search by name..."
          value={nameSearch}
          onChange={handleSearchChange}
          className="h-9 w-48"
        />
        <Select onValueChange={handleAssetTypeChange} defaultValue="all">
          <SelectTrigger className="h-9 w-44">
            <SelectValue placeholder="Asset type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {ASSET_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select onValueChange={handlePrimitiveChange} defaultValue="all">
          <SelectTrigger className="h-9 w-44">
            <SelectValue placeholder="Primitive" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All primitives</SelectItem>
            {PRIMITIVES.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      )}

      {!isLoading && isError && (
        <p className="text-sm text-destructive">Failed to load crypto assets.</p>
      )}

      {!isLoading && !isError && data && data.items.length === 0 && (
        <p className="text-sm text-muted-foreground">No crypto assets found.</p>
      )}

      {!isLoading && !isError && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Primitive</TableHead>
                <TableHead>Key Size</TableHead>
                <TableHead>Curve</TableHead>
                <TableHead>Occurrences</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((asset) => (
                <TableRow
                  key={asset._id}
                  className="cursor-pointer"
                  onClick={() => onSelect(asset)}
                >
                  <TableCell className="font-medium">{asset.name}</TableCell>
                  <TableCell className="capitalize">{asset.asset_type}</TableCell>
                  <TableCell>{asset.primitive ?? "—"}</TableCell>
                  <TableCell>
                    {asset.key_size_bits != null ? `${asset.key_size_bits} bits` : "—"}
                  </TableCell>
                  <TableCell>{asset.curve ?? "—"}</TableCell>
                  <TableCell>{asset.occurrence_locations.length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <span className="text-sm text-muted-foreground">
                Page {currentPage} of {totalPages} ({data.total} total)
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={skip === 0}
                  onClick={() => setSkip(Math.max(0, skip - PAGE_SIZE))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={skip + PAGE_SIZE >= data.total}
                  onClick={() => setSkip(skip + PAGE_SIZE)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
