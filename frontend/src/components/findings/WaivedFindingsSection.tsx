import { useQuery } from "@tanstack/react-query";
import { ShieldOff } from "lucide-react";
import { scanApi } from "@/api/scans";
import { FindingsTable } from "./FindingsTable";
import { ScanContext } from "./details/SastDetailsView";

interface WaivedFindingsSectionProps {
    scanId: string;
    projectId: string;
    category?: string;
    licenseCategory?: string;
    scanContext?: ScanContext;
    /** Top offset (px) for the inner table's sticky header. */
    stickyHeaderTop?: number;
}

/**
 * Renders a secondary, visually de-emphasised list of waived findings beneath
 * the primary list. Self-hides when there are zero waived findings in scope so
 * users only see the section when there's something to look at.
 *
 * Stats elsewhere already exclude waived findings (see backend stats.py); this
 * is purely for transparency — "what is currently being suppressed?".
 */
export function WaivedFindingsSection({
    scanId,
    projectId,
    category,
    licenseCategory,
    scanContext,
    stickyHeaderTop,
}: Readonly<WaivedFindingsSectionProps>) {
    // Cheap probe: limit=1 just to learn whether any waived finding matches
    // the active category filter. The full table below paginates separately.
    const { data: probe } = useQuery({
        queryKey: ['waived-findings-probe', scanId, category, licenseCategory],
        queryFn: () =>
            scanApi.getFindings(scanId, {
                skip: 0,
                limit: 1,
                category,
                ...(licenseCategory ? { license_category: licenseCategory } : {}),
                waived: true,
            }),
    });

    const total = probe?.total ?? 0;
    if (total === 0) return null;

    return (
        <section className="mt-8 opacity-70">
            <header className="mb-2 flex items-center gap-2 text-sm text-muted-foreground">
                <ShieldOff className="h-4 w-4" aria-hidden />
                <h3 className="font-medium">Waived findings</h3>
                <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{total}</span>
                <span className="text-xs">— excluded from statistics</span>
            </header>
            <div className="rounded-md border bg-muted/30">
                <FindingsTable
                    scanId={scanId}
                    projectId={projectId}
                    category={category}
                    licenseCategory={licenseCategory}
                    scanContext={scanContext}
                    stickyHeaderTop={stickyHeaderTop}
                    waivedFilter="waived"
                />
            </div>
        </section>
    );
}
