export function extractErrorMessage(err: unknown): string {
  if (err && typeof err === "object") {
    const e = err as {
      response?: { data?: { detail?: string | { msg?: string }[] | Record<string, unknown> } };
      message?: string;
    };
    const detail = e.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
    if (detail) return JSON.stringify(detail);
    if (e.message) return e.message;
  }
  return "Unknown error";
}
