import { useMemo, useState } from "react";
import { Database, Search } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { useJobStateContext } from "../contexts/JobStateContext";
import { EVIDENCE_CATEGORY_LABELS } from "../lib/api";

function formatValue(valueJson: string): string {
  try {
    const parsed = JSON.parse(valueJson);
    if (typeof parsed === "string") return parsed;
    return JSON.stringify(parsed, null, 2);
  } catch {
    return valueJson;
  }
}

export function EvidencePage() {
  const jobState = useJobStateContext();
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  const categories = useMemo(
    () => Array.from(new Set(jobState.evidence.map((e) => e.category))),
    [jobState.evidence]
  );

  const filtered = useMemo(() => {
    let next = jobState.evidence;
    if (categoryFilter !== "all") next = next.filter((e) => e.category === categoryFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      next = next.filter(
        (e) => e.label.toLowerCase().includes(q) || e.value_json.toLowerCase().includes(q)
      );
    }
    return next;
  }, [jobState.evidence, categoryFilter, search]);

  const grouped = useMemo(() => {
    const map = new Map<string, typeof filtered>();
    for (const item of filtered) {
      const list = map.get(item.category) ?? [];
      list.push(item);
      map.set(item.category, list);
    }
    return map;
  }, [filtered]);

  return (
    <AppShell
      title="Evidence"
      subtitle={jobState.activeJob ? `Raw extraction register — ${jobState.evidence.length} items` : "No active job"}
    >
      <div className="bg-card border border-border rounded-xl">
        <div className="p-6 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">
              Evidence Register
            </h2>
            <h3 className="text-xl font-bold text-foreground">Everything the tools actually extracted</h3>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search evidence..."
                className="bg-secondary text-sm rounded-lg pl-8 pr-3 py-2 outline-none focus:ring-1 focus:ring-accent w-52"
              />
            </div>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-secondary text-sm font-semibold border-none rounded-lg px-3 py-2 outline-none focus:ring-1 focus:ring-accent text-foreground cursor-pointer"
            >
              <option value="all">All Categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {EVIDENCE_CATEGORY_LABELS[c] ?? c}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="p-6">
          {jobState.evidence.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <Database size={48} className="mb-4 opacity-40" />
              <p className="text-lg font-semibold">No evidence extracted yet.</p>
              <p className="text-sm mt-1">Run a scan to populate the evidence register.</p>
            </div>
          ) : (
            <div className="flex flex-col gap-8">
              {Array.from(grouped.entries()).map(([category, items]) => (
                <div key={category}>
                  <div className="flex items-center gap-2 mb-3">
                    <h4 className="text-sm font-bold text-accent uppercase tracking-wide">
                      {EVIDENCE_CATEGORY_LABELS[category] ?? category}
                    </h4>
                    <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded-full">
                      {items.length}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {items.map((item) => (
                      <div key={item.id} className="border border-border rounded-lg p-4 bg-[#0a0e13]">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-semibold text-foreground">{item.label}</span>
                          <span className="text-[10px] font-mono text-muted-foreground bg-secondary px-1.5 py-0.5 rounded">
                            {item.evidence_type}
                          </span>
                        </div>
                        <pre className="text-xs font-mono text-foreground/80 whitespace-pre-wrap break-all leading-relaxed">
                          {formatValue(item.value_json)}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
