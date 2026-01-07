export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface ApiErrorResponse {
  detail?: string;
  message?: string;
}
