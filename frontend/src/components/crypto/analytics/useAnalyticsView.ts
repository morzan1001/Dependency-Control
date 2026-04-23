import { useSearchParams } from "react-router-dom";
import type { AnalyticsView } from "./AnalyticsViewSwitcher";

/**
 * Reads the currently selected analytics view from the URL (`?analytics_view=`),
 * falling back to `defaultView` when the param is absent.
 *
 * Lives in its own module so `AnalyticsViewSwitcher.tsx` exports only its
 * component (keeps React Fast Refresh happy).
 */
export function useAnalyticsView(defaultView: AnalyticsView = "table"): AnalyticsView {
  const [params] = useSearchParams();
  return (params.get("analytics_view") as AnalyticsView) ?? defaultView;
}
