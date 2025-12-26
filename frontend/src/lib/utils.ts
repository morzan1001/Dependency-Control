import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
 
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

interface ValidationError {
  msg: string;
  type?: string;
  loc?: (string | number)[];
}

interface ErrorWithResponse {
  response?: {
    data?: {
      detail?: string | ValidationError[];
    };
  };
  message?: string;
}

export function getErrorMessage(error: ErrorWithResponse | Error | unknown): string {
  if (typeof error !== 'object' || error === null) {
    return "An unknown error occurred";
  }
  
  const err = error as ErrorWithResponse;
  if (err.response?.data?.detail) {
    const detail = err.response.data.detail;
    if (Array.isArray(detail)) {
      // Handle validation errors array (FastAPI standard)
      return detail.map((validationErr: ValidationError) => {
        // Remove "Value error, " prefix if present, as it's added by Pydantic
        return validationErr.msg.replace('Value error, ', '');
      }).join('\n');
    }
    if (typeof detail === 'string') {
      return detail;
    }
  }
  return (error as Error).message || "An unknown error occurred";
}
