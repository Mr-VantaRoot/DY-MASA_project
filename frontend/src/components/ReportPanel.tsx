import { Download, FileText } from "lucide-react";
import type { AnalysisJob, ReasoningItem, ReportItem } from "../types";
import { API_BASE_URL } from "../lib/api";

export function ReportPanel({ reasoning, reports, activeJob }: { reasoning: ReasoningItem | null, reports: ReportItem[], activeJob: AnalysisJob | null }) {
  const pdfReport = reports.find(r => r.report_type === "pdf") || reports[0] || null;

  return (
    <div className="bg-card border border-border rounded-xl p-6 flex flex-col h-[400px]">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">Deliverable</h2>
          <h3 className="text-xl font-bold text-foreground">Structured Reasoning & Export</h3>
        </div>
        <FileText className="text-muted-foreground" size={24} />
      </div>

      <div className="flex-1 flex flex-col justify-between overflow-hidden">
        <div className="bg-[#0a0e13] border border-border rounded-lg p-5 flex-1 overflow-y-auto relative">
          {!reasoning && activeJob?.status === "running" ? (
             <div className="absolute inset-0 shimmer opacity-50 rounded-lg"></div>
          ) : !reasoning ? (
             <p className="text-muted-foreground italic text-sm">The structured reasoning summary will appear once evidence-backed findings are generated.</p>
          ) : (
            <blockquote className="border-l-4 border-accent pl-4">
              <strong className="text-xs uppercase text-muted-foreground tracking-wider mb-2 block">{reasoning.provider} Summary</strong>
              <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">{reasoning.summary}</p>
            </blockquote>
          )}
        </div>

        <div className="mt-4 pt-4 border-t border-border">
          {pdfReport && activeJob ? (
            <a
              href={`${API_BASE_URL}/jobs/${activeJob.id}/reports/${pdfReport.id}/download`}
              target="_blank"
              rel="noreferrer"
              className="w-full flex items-center justify-center gap-2 bg-accent text-accent-foreground font-bold py-3 rounded-lg hover:brightness-110 transition-all active:scale-[0.98]"
            >
              <Download size={18} />
              Download {pdfReport.report_type.toUpperCase()} Report
            </a>
          ) : (
            <button disabled className="w-full flex items-center justify-center gap-2 bg-secondary text-muted-foreground font-bold py-3 rounded-lg opacity-70 cursor-not-allowed">
              <Download size={18} />
              Waiting for report generation
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
