import { useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";

export type AnalyticsView =
  | "table" | "heatmap" | "treemap" | "bar";

interface Props {
  availableViews: AnalyticsView[];
  defaultView?: AnalyticsView;
}

const LABEL: Record<AnalyticsView, string> = {
  table: "Table",
  heatmap: "Heatmap",
  treemap: "Treemap",
  bar: "Top-N",
};

export function AnalyticsViewSwitcher({ availableViews, defaultView = "table" }: Props) {
  const [params, setParams] = useSearchParams();
  const current = (params.get("analytics_view") as AnalyticsView) ?? defaultView;
  return (
    <div className="inline-flex gap-1 rounded-md border p-1 bg-background">
      {availableViews.map((v) => (
        <Button
          key={v}
          variant={current === v ? "default" : "ghost"}
          size="sm"
          onClick={() => {
            const next = new URLSearchParams(params);
            next.set("analytics_view", v);
            setParams(next, { replace: true });
          }}
        >
          {LABEL[v]}
        </Button>
      ))}
    </div>
  );
}
