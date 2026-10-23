import { useState, useMemo } from "react";
import { Filter, ShieldAlert, ChevronDown, ChevronUp } from "lucide-react";
import type { FindingItem, Severity } from "../types";
import { SEVERITY_ORDER, SEVERITY_LABELS } from "../lib/api";

export function FindingsList({ findings }: { findings: FindingItem[] }) {
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"severity" | "title" | "category">("severity");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const categories = useMemo(() => Array.from(new Set(findings.map(f => f.category))), [findings]);

  const filtered = useMemo(() => {
    let next = [...findings];
    if (severityFilter !== "all") next = next.filter(f => f.severity === severityFilter);
    if (categoryFilter !== "all") next = next.filter(f => f.category === categoryFilter);

    return next.sort((a, b) => {
      if (sortBy === "title") return a.title.localeCompare(b.title);
      if (sortBy === "category") return a.category.localeCompare(b.category);
      return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    });
  }, [findings, severityFilter, categoryFilter, sortBy]);

  const severityColors = {
    critical: "border-l-critical bg-[#111820]/90",
    high: "border-l-high bg-card",
    medium: "border-l-medium bg-card",
    low: "border-l-low bg-card",
    info: "border-l-info bg-card",
  };

  const badgeColors = {
    critical: "bg-critical/10 text-critical border-critical/20",
    high: "bg-high/10 text-high border-high/20",
    medium: "bg-medium/10 text-medium border-medium/20",
    low: "bg-low/10 text-low border-low/20",
    info: "bg-info/10 text-info border-info/20",
  };

  return (
    <div className="bg-card border border-border rounded-xl flex flex-col">
      <div className="p-6 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">Findings</h2>
          <h3 className="text-xl font-bold text-foreground">Evidence-backed triage</h3>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex p-1 bg-secondary rounded-lg">
            <button
              onClick={() => setSeverityFilter("all")}
              className={`px-3 py-1.5 text-xs font-bold rounded-md transition-colors ${severityFilter === "all" ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
            >
              All
            </button>
            {SEVERITY_LABELS.map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1.5 text-xs font-bold rounded-md capitalize transition-colors ${severityFilter === sev ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
              >
                {sev}
              </button>
            ))}
          </div>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-secondary text-sm font-semibold border-none rounded-lg px-3 py-2 outline-none focus:ring-1 focus:ring-accent text-foreground cursor-pointer"
          >
            <option value="all">All Categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as "severity" | "title" | "category")}
            className="bg-secondary text-sm font-semibold border-none rounded-lg px-3 py-2 outline-none focus:ring-1 focus:ring-accent text-foreground cursor-pointer"
          >
            <option value="severity">Sort: Severity</option>
            <option value="title">Sort: Title</option>
            <option value="category">Sort: Category</option>
          </select>
        </div>
      </div>

      <div className="p-6 flex flex-col gap-4 min-h-[300px]">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center flex-1 py-12 text-muted-foreground">
            <ShieldAlert size={48} className="mb-4 opacity-50" />
            <p className="text-lg font-semibold">No findings match the current filters.</p>
          </div>
        ) : (
          filtered.map(finding => {
            const isExpanded = expandedId === finding.id;
            let evidenceIds: string[] = [];
            try { evidenceIds = JSON.parse(finding.evidence_ids_json); } catch(e){}

            return (
              <div
                key={finding.id}
                className={`border border-border border-l-[4px] rounded-lg transition-all duration-200 overflow-hidden ${severityColors[finding.severity]} ${finding.severity === 'critical' ? 'shadow-[0_4px_24px_rgba(239,68,68,0.08)]' : ''}`}
              >
                <div
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-secondary/30 transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                >
                  <div className="flex items-center gap-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${badgeColors[finding.severity]}`}>
                      {finding.severity}
                    </span>
                    <h4 className="font-bold text-foreground text-sm md:text-base">{finding.title}</h4>
                    <span className="hidden md:inline-block text-xs font-mono text-muted-foreground bg-secondary px-2 py-1 rounded">{finding.category}</span>
                  </div>
                  <button className="text-muted-foreground hover:text-foreground transition-colors p-1">
                    {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                  </button>
                </div>

                <div className={`transition-all duration-300 ease-in-out px-4 flex flex-col gap-4 overflow-hidden ${isExpanded ? 'max-h-[800px] opacity-100 pb-4' : 'max-h-0 opacity-0 pb-0'}`}>
                  <div className="pt-2 border-t border-border/50 text-sm text-foreground/90 leading-relaxed">
                    <p>{finding.description}</p>
                  </div>

                  {finding.remediation && (
                    <div className="bg-secondary/50 rounded-md p-4 border border-border">
                      <strong className="text-xs uppercase text-muted-foreground tracking-wider mb-2 block">Remediation</strong>
                      <p className="text-sm text-foreground/80">{finding.remediation}</p>
                    </div>
                  )}

                  {evidenceIds.length > 0 && (
                    <div>
                      <strong className="text-xs uppercase text-muted-foreground tracking-wider mb-2 block">Evidence Refs</strong>
                      <div className="flex flex-wrap gap-2">
                        {evidenceIds.map(id => (
                          <span key={id} className="text-xs font-mono bg-[#060a0d] border border-border px-2 py-1 rounded text-accent">
                            {id}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  );
}
