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

/**
 * Extract a human-readable message from an unknown error.
 *
 * Behavior is kept identical to `getErrorMessage` in `lib/utils.ts` so that the
 * same-shaped backend error renders the same string regardless of which page
 * raised it: FastAPI validation arrays are joined and the `Value error, `
 * prefix is stripped, string details pass through, and the fallback text
 * matches. The one addition over `getErrorMessage` is that non-string,
 * non-array (object) details are serialized rather than dropped.
 */
export function extractErrorMessage(err: unknown): string {
  if (typeof err !== "object" || err === null) {
    return "An unknown error occurred";
  }

  const e = err as ErrorWithResponse;
  const detail = e.response?.data?.detail;
  if (detail) {
    if (Array.isArray(detail)) {
      return detail
        .map((validationErr: ValidationError) => validationErr.msg.replace("Value error, ", ""))
        .join("\n");
    }
    if (typeof detail === "string") {
      return detail;
    }
    return JSON.stringify(detail);
  }
  return e.message || "An unknown error occurred";
}
