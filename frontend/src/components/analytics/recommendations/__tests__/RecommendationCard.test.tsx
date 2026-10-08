import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect } from 'vitest'

import { RecommendationCard } from '../RecommendationCard'
import type { Recommendation, RecommendationAction } from '@/types/analytics'

const COMPONENTS_LISTED = 20
const COMPONENTS_COVERED = 900
const FILES_LISTED = 5
const RANK = 3
const RANKED_OUT_OF = 43

function makeRecommendation(action: RecommendationAction, over: Partial<Recommendation> = {}): Recommendation {
  return {
    type: 'recurring_vulnerability',
    priority: 'high',
    title: 'Test recommendation',
    description: 'A test recommendation',
    impact: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
    affected_components: [],
    affected_components_total: 0,
    rank: 0,
    ranked_out_of: 0,
    action,
    effort: 'medium',
    ...over,
  }
}

function components(count: number): string[] {
  return Array.from({ length: count }, (_, index) => `pkg${index}@1.0.0`)
}

function renderExpanded(recommendation: Recommendation) {
  render(
    <MemoryRouter>
      <RecommendationCard recommendation={recommendation} />
    </MemoryRouter>,
  )
  fireEvent.click(screen.getByRole('button', { expanded: false }))
}

describe('RecommendationCard CVE rendering', () => {
  it('renders each recurring CVE only once', () => {
    renderExpanded(
      makeRecommendation({
        type: 'address_recurring',
        cves: [{ cve: 'CVE-2021-0001', components: ['lodash'], scans: 3 }],
      }),
    )
    expect(screen.getAllByText('CVE-2021-0001')).toHaveLength(1)
  })

  it('names the components and scans of each recurring CVE', () => {
    renderExpanded(
      makeRecommendation({
        type: 'address_recurring',
        cves: [{ cve: 'CVE-2021-0001', components: ['lodash', 'lodash-es'], scans: 4 }],
      }),
    )
    expect(screen.getByText('lodash, lodash-es · 4 scans')).toBeInTheDocument()
  })

  it('renders each cross-project CVE only once', () => {
    renderExpanded(
      makeRecommendation({
        type: 'fix_cross_project_vuln',
        cves: [{ cve: 'CVE-2021-0002', total_affected: 3, affected_projects: ['a', 'b', 'c'] }],
      }),
    )
    expect(screen.getAllByText('CVE-2021-0002')).toHaveLength(1)
  })

  it('names the components the recommendation covers, not the ones it listed', () => {
    renderExpanded(
      makeRecommendation(
        { type: 'update_dependency' },
        {
          affected_components: components(COMPONENTS_LISTED),
          affected_components_total: COMPONENTS_COVERED,
        },
      ),
    )
    expect(
      screen.getByText(`Affected Components (${COMPONENTS_LISTED} of ${COMPONENTS_COVERED.toLocaleString()})`),
    ).toBeInTheDocument()
  })

  it('counts the unlisted files against the population, not against the sample it was given', () => {
    const filesTotal = 900
    renderExpanded(
      makeRecommendation({
        type: 'fix_code',
        files: components(COMPONENTS_LISTED),
        files_total: filesTotal,
      }),
    )
    expect(screen.getByText(`...and ${(filesTotal - FILES_LISTED).toLocaleString()} more`)).toBeInTheDocument()
  })

  it('says a card is one of a ranked list that was cut', () => {
    render(
      <MemoryRouter>
        <RecommendationCard
          recommendation={makeRecommendation({ type: 'update_dependency' }, { rank: RANK, ranked_out_of: RANKED_OUT_OF })}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText(`Ranked ${RANK} of ${RANKED_OUT_OF}`)).toBeInTheDocument()
  })

  it('says nothing about rank when the generator emitted its whole list', () => {
    render(
      <MemoryRouter>
        <RecommendationCard recommendation={makeRecommendation({ type: 'update_dependency' })} />
      </MemoryRouter>,
    )
    expect(screen.queryByText(/^Ranked /)).not.toBeInTheDocument()
  })

  it('counts the findings a card addresses', () => {
    render(
      <MemoryRouter>
        <RecommendationCard recommendation={makeRecommendation({ type: 'update_dependency' })} />
      </MemoryRouter>,
    )
    expect(screen.getByText('addressed')).toBeInTheDocument()
  })

  it('breaks the vulnerability count down by severity on focus', async () => {
    render(
      <MemoryRouter>
        <RecommendationCard recommendation={makeRecommendation({ type: 'update_dependency' })} />
      </MemoryRouter>,
    )
    fireEvent.focus(screen.getByText('addressed').parentElement!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('High: 1')
  })

  it('opens no empty breakdown for a count that carries no severities', () => {
    render(
      <MemoryRouter>
        <RecommendationCard
          recommendation={makeRecommendation(
            { type: 'fix_cross_project_vuln', cves: [{ cve: 'CVE-2021-0002', total_affected: 3 }] },
            { type: 'shared_vulnerability', impact: { total: 3 } },
          )}
        />
      </MemoryRouter>,
    )
    fireEvent.focus(screen.getByText('addressed').parentElement!)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('shows no count on a hygiene card, which counts no findings', () => {
    render(
      <MemoryRouter>
        <RecommendationCard
          recommendation={makeRecommendation({ type: 'audit_dependencies' }, { impact: { total: 0 } })}
        />
      </MemoryRouter>,
    )
    expect(screen.queryByText('addressed')).not.toBeInTheDocument()
  })

  it('badges a license-drift card as such and does not call the drifted components fixed vulnerabilities', () => {
    render(
      <MemoryRouter>
        <RecommendationCard
          recommendation={makeRecommendation({ type: 'review_license_drift' }, { type: 'license_drift', impact: { total: 3 } })}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText('License Drift')).toBeInTheDocument()
    expect(screen.queryByText('Dependency Update')).not.toBeInTheDocument()
    expect(screen.queryByText('vulns fixed')).not.toBeInTheDocument()
    expect(screen.getByText('addressed')).toBeInTheDocument()
  })

  it('names a card type without its own entry after the type, not as a dependency update', () => {
    render(
      <MemoryRouter>
        <RecommendationCard
          recommendation={makeRecommendation({ type: 'replace_algorithm' }, { type: 'replace_weak_algorithm' })}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText('Replace Weak Algorithm')).toBeInTheDocument()
    expect(screen.queryByText('Dependency Update')).not.toBeInTheDocument()
  })

  it('still renders the generic Related Vulnerabilities block for other action types', () => {
    renderExpanded(
      makeRecommendation({
        type: 'update_dependency',
        cves: ['CVE-2021-0003'],
      }),
    )
    expect(screen.getByText('Related Vulnerabilities')).toBeInTheDocument()
    expect(screen.getAllByText('CVE-2021-0003')).toHaveLength(1)
  })
})

describe('RecommendationCard steps', () => {
  it('numbers the steps of any action type in order', () => {
    const steps = ['Remove the package', 'Rotate exposed credentials']
    renderExpanded(makeRecommendation({ type: 'fix_hotspot', steps }))

    const list = screen.getByText(steps[0]).closest('ol')
    expect(list).not.toBeNull()
    expect(Array.from(list!.querySelectorAll('li'), (li) => li.textContent)).toEqual(steps)
  })
})

describe("RecommendationCard action sections", () => {
  // The action box sits right below its heading.
  function actionBox(title: string): HTMLElement {
    return screen.getByText(title).nextElementSibling as HTMLElement;
  }
  const classesOf = (element: Element) => new Set(element.className.split(" "));

  it.each([
    [{ type: "update_dependency", package: "lodash", current_version: "1", target_version: "2" }, "Recommended Action", "bg-muted rounded-lg p-3 font-mono text-sm"],
    [{ type: "update_base_image", current_image: "node:18" }, "Base Image", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "update_transitive", package: "lodash", target_version: "2" }, "How to Fix", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "fix_code", files: ["a.py"] }, "Code Security Issues", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "deduplicate_versions", packages: [{ name: "lodash", versions: ["1", "2"] }] }, "Version Fragmentation", "bg-muted rounded-lg p-3 text-sm space-y-3 max-h-[300px] overflow-y-auto"],
    [{ type: "investigate_regression", suggestion: "Look" }, "Regression Details", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "address_recurring", cves: [] }, "Recurring Issues", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "reduce_chain_depth", deepest_chains: [{ package: "a", depth: 9 }] }, "Deep Dependency Chains", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "consolidate_packages", duplicates: [{ category: "http", found: ["a", "b"], suggestion: "pick one" }] }, "Duplicate Functionality", "bg-muted rounded-lg p-3 text-sm space-y-3"],
    [{ type: "fix_cross_project_vuln", cves: [] }, "Cross-Project Vulnerabilities", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "prioritize_projects", priority_projects: [{ name: "p", id: "p", critical: 1, high: 2 }] }, "Priority Projects", "bg-muted rounded-lg p-3 text-sm space-y-2"],
    [{ type: "standardize_versions", packages: [{ name: "lodash", versions: ["1", "2"] }] }, "Version Standardization Across Projects", "bg-muted rounded-lg p-3 text-sm space-y-3"],
  ] as [RecommendationAction, string, string][])("boxes the %o action under its heading", (action, title, boxClasses) => {
    renderExpanded(makeRecommendation(action));

    const heading = screen.getByText(title);
    expect(heading.className).toBe("text-sm font-medium flex items-center gap-2");
    expect(heading.parentElement!.className).toBe("space-y-2");
    expect(classesOf(actionBox(title))).toEqual(new Set(boxClasses.split(" ")));
  });

  it("marks a regression's heading icon as destructive", () => {
    renderExpanded(makeRecommendation({ type: "investigate_regression", suggestion: "Look" }));

    expect(screen.getByText("Regression Details").querySelector("svg")!.classList).toContain("text-destructive");
  });

  it("lists the deduplication commands below the package box", () => {
    renderExpanded(
      makeRecommendation({ type: "deduplicate_versions", packages: [{ name: "lodash", versions: ["1"] }], commands: ["npm dedupe"] }),
    );

    const commands = screen.getByText("npm dedupe").parentElement!;
    expect(actionBox("Version Fragmentation").nextElementSibling).toBe(commands);
    expect(classesOf(commands)).toEqual(new Set("mt-3 p-2 bg-muted/50 rounded font-mono text-xs text-muted-foreground".split(" ")));
  });
});

describe("RecommendationCard copy button", () => {
  it("swallows a rejected clipboard write instead of leaving an unhandled rejection", async () => {
    const rejections: unknown[] = [];
    const onRejection = (reason: unknown) => rejections.push(reason);
    process.on("unhandledRejection", onRejection);
    const written: string[] = [];
    // A plain function: a vi.fn spy attaches its own handler to the promise it returns.
    const writeText = (text: string) => {
      written.push(text);
      return Promise.reject(new Error("denied"));
    };
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    renderExpanded(makeRecommendation({ type: "update_dependency", package: "lodash", target_version: "2" }));
    fireEvent.click(screen.getByText("Recommended Action").nextElementSibling!.querySelector("button")!);
    await new Promise((resolve) => setTimeout(resolve, 50));
    process.off("unhandledRejection", onRejection);

    expect(written).toEqual(["lodash@2"]);
    expect(rejections).toEqual([]);
  });
});
