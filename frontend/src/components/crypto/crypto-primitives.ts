/**
 * Canonical list of crypto primitive kinds, kept in a dedicated module so
 * downstream call sites (rule editors, future AddRuleDialog) can import the
 * single source of truth without dragging in the editor component.
 */
import type { CryptoPrimitive } from "@/types/crypto";

export const PRIMITIVES: CryptoPrimitive[] = [
  "block-cipher",
  "stream-cipher",
  "hash",
  "mac",
  "pke",
  "signature",
  "kem",
  "kdf",
  "drbg",
  "other",
];
