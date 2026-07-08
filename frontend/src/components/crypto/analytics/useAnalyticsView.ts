import { useSearchParams } from "react-router-dom";
import type { AnalyticsView } from "./AnalyticsViewSwitcher";

// Separate module so AnalyticsViewSwitcher.tsx exports only its component (React Fast Refresh).
export function useAnalyticsView(defaultView: AnalyticsView = "table"): AnalyticsView {
  const [params] = useSearchParams();
  return (params.get("analytics_view") as AnalyticsView) ?? defaultView;
}
