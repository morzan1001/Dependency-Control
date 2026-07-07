interface ValidationError {
  msg: string;
  type?: string;
  loc?: (string | number)[];
}

interface ErrorWithResponse {
  response?: {
    data?: {
      detail?: string | ValidationError[] | Record<string, unknown>;
    };
  };
  message?: string;
}

// Human-readable message from an unknown error: joins FastAPI validation arrays
// (stripping the "Value error, " prefix), passes string details through, and
// serializes object details.
export function extractErrorMessage(err: unknown): string {
  if (typeof err !== "object" || err === null) {
    return "An unknown error occurred";
  }

  const e = err as ErrorWithResponse;
  const detail = e.response?.data?.detail;
  if (detail) {
    if (Array.isArray(detail)) {
      return detail
        .map((validationErr: ValidationError) => (validationErr.msg ?? String(validationErr)).replace("Value error, ", ""))
        .join("\n");
    }
    if (typeof detail === "string") {
      return detail;
    }
    return JSON.stringify(detail);
  }
  return e.message || "An unknown error occurred";
}
