import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
 
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getErrorMessage(error: any): string {
  if (error.response?.data?.detail) {
    const detail = error.response.data.detail;
    if (Array.isArray(detail)) {
      // Handle validation errors array (FastAPI standard)
      return detail.map((err: any) => {
        // Remove "Value error, " prefix if present, as it's added by Pydantic
        return err.msg.replace('Value error, ', '');
      }).join('\n');
    }
    if (typeof detail === 'string') {
      return detail;
    }
  }
  return error.message || "An unknown error occurred";
}
