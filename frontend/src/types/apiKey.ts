/** What a saturated key listing left out; null while the listing is the whole of it. */
export interface KeyListTruncation {
  limit: number;
  returned: number;
  total: number;
}
