import { XCircle } from "lucide-react";
import type { AnalysisJob } from "../types";
import { StatusPill } from "./StatusPill";

export function JobStatusPanel({
  activeJob,
  evidenceCount,
  findingsCount,
  onDropAnalysis,
  isDropping = false,
}: {
  activeJob: AnalysisJob | null,
  evidenceCount: number,
  findingsCount: number,
  onDropAnalysis?: () => void,
  isDropping?: boolean,
}) {
  if (!activeJob) {
    return (
      <div className="bg-card border border-border rounded-xl p-6 min-h-[220px] flex items-center justify-center">
        <p className="text-muted-foreground">Upload an APK to create the first job.</p>
      </div>
    );
  }

  const canDrop = activeJob.status === "queued" || activeJob.status === "running";

  return (
    <div className="bg-card border border-border rounded-xl p-6 flex flex-col justify-between">
      <div>
        <div className="flex items-start justify-between gap-4 mb-6">
          <div>
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">Active Job</h2>
            <h3 className="text-xl font-bold text-foreground break-all">{activeJob.original_filename}</h3>
          <p className="text-[11px] text-muted-foreground mt-2">
            Ghidra native analysis: <span className={activeJob.ghidra_enabled ? "text-accent font-bold" : "font-bold"}>{activeJob.ghidra_enabled ? "ON" : "OFF"}</span>
          </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <StatusPill status={activeJob.status} />
            {canDrop && onDropAnalysis && (
              <button
                type="button"
                onClick={onDropAnalysis}
                disabled={isDropping}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border bg-critical/10 text-critical border-critical/40 hover:bg-critical/20 disabled:opacity-50"
                title="Drop this analysis and delete its files"
              >
                <XCircle size={14} />
                Drop
              </button>
            )}
          </div>
        </div>

        <p className="text-sm text-foreground/80 mb-6 font-medium">
          {activeJob.status === "failed" ? (
            <span className="text-critical">{activeJob.error_message || "Analysis stopped due to an error."}</span>
          ) : activeJob.status === "cancelled" ? (
            <span className="text-critical">Analysis cancelled and cleanup requested.</span>
          ) : activeJob.status === "completed" ? (
            "Analysis completed. Review findings below."
          ) : (
            activeJob.current_step || "Initializing..."
          )}
        </p>
      </div>

      <div>
        <div className="w-full bg-secondary h-1.5 rounded-full overflow-hidden mb-4">
          <div
            className="h-full bg-accent transition-all duration-300 ease-out"
            style={{ width: `${activeJob.progress}%` }}
          />
        </div>

        <div className="grid grid-cols-4 gap-4">
          <div className="flex flex-col">
            <span className="text-[10px] uppercase font-bold text-muted-foreground">Size</span>
            <span className="text-sm font-mono mt-1">{(activeJob.file_size_bytes / (1024*1024)).toFixed(1)}MB</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] uppercase font-bold text-muted-foreground">Evidence</span>
            <span className="text-sm font-mono mt-1">{evidenceCount}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] uppercase font-bold text-muted-foreground">Findings</span>
            <span className="text-sm font-mono mt-1">{findingsCount}</span>
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-[10px] uppercase font-bold text-muted-foreground">SHA256</span>
            <span className="text-sm font-mono mt-1 truncate" title={activeJob.sha256 || "Pending"}>{activeJob.sha256 || "Pending"}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
