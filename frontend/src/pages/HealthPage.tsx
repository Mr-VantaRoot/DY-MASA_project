import { useEffect, useState, useCallback } from "react";
import { CheckCircle2, XCircle, RefreshCw, Database } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { fetchHealth } from "../lib/api";

type ToolHealth = { name: string; available: boolean; command: string[]; version: string | null; error: string | null };
type HealthResponse = { status: string; app_name: string; app_version: string; database: boolean; tools: ToolHealth[] };

export function HealthPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchHealth();
      setHealth(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reach backend.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = window.setInterval(load, 10000);
    return () => window.clearInterval(id);
  }, [load]);

  return (
    <AppShell title="System Health" subtitle="Backend, database, and required local tooling">
      <div className="flex items-center justify-between">
        <div
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-bold border ${
            health?.status === "ok"
              ? "bg-[#052e25] text-[#00d4aa] border-[#00d4aa]/40"
              : "bg-critical/10 text-critical border-critical/40"
          }`}
        >
          {health?.status === "ok" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
          {health ? `${health.app_name} v${health.app_version} — ${health.status.toUpperCase()}` : "Checking..."}
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 text-xs font-bold text-muted-foreground hover:text-foreground"
        >
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      {error && (
        <div className="bg-critical/10 border border-critical/30 rounded-lg p-4 text-sm text-critical">{error}</div>
      )}

      {health && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border border-border rounded-xl p-5 bg-card flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Database size={20} className="text-accent" />
              <div>
                <p className="text-sm font-bold">PostgreSQL</p>
                <p className="text-xs text-muted-foreground">Persistence layer</p>
              </div>
            </div>
            {health.database ? (
              <span className="text-xs font-bold text-[#00d4aa] flex items-center gap-1">
                <CheckCircle2 size={14} /> Connected
              </span>
            ) : (
              <span className="text-xs font-bold text-critical flex items-center gap-1">
                <XCircle size={14} /> Unreachable
              </span>
            )}
          </div>

          {health.tools.map((tool) => (
            <div key={tool.name} className="border border-border rounded-xl p-5 bg-card">
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-bold capitalize">{tool.name}</p>
                {tool.available ? (
                  <span className="text-xs font-bold text-[#00d4aa] flex items-center gap-1">
                    <CheckCircle2 size={14} /> Available
                  </span>
                ) : (
                  <span className="text-xs font-bold text-critical flex items-center gap-1">
                    <XCircle size={14} /> Missing
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground font-mono truncate">{tool.command.join(" ")}</p>
              {tool.version && <p className="text-xs text-muted-foreground mt-1">v{tool.version}</p>}
              {tool.error && <p className="text-xs text-critical mt-1">{tool.error}</p>}
            </div>
          ))}
        </div>
      )}
    </AppShell>
  );
}
