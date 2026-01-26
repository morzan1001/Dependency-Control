export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'INFO' | 'UNKNOWN';

export type ObjectId = string;

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}
