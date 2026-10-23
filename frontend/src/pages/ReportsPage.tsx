import { Download, FileText, FileCode2 } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { useJobStateContext } from "../contexts/JobStateContext";
import { API_BASE_URL } from "../lib/api";

export function ReportsPage() {
  const jobState = useJobStateContext();

  return (
    <AppShell
      title="Reports"
      subtitle={jobState.activeJob ? `Exportable deliverables for ${jobState.activeJob.original_filename}` : "No active job"}
    >
      <div className="bg-card border border-border rounded-xl p-6">
        <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">Deliverables</h2>
        <h3 className="text-xl font-bold text-foreground mb-6">Generated Reports</h3>

        {jobState.reports.length === 0 || !jobState.activeJob ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <FileText size={48} className="mb-4 opacity-40" />
            <p className="text-lg font-semibold">No reports generated yet.</p>
            <p className="text-sm mt-1">Reports are produced automatically once a scan completes.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {jobState.reports.map((report) => (
              <div
                key={report.id}
                className="border border-border rounded-lg p-5 flex items-center justify-between bg-[#0a0e13]"
              >
                <div className="flex items-center gap-3 min-w-0">
                  {report.report_type === "pdf" ? (
                    <FileText size={22} className="text-critical shrink-0" />
                  ) : (
                    <FileCode2 size={22} className="text-low shrink-0" />
                  )}
                  <div className="min-w-0">
                    <p className="text-sm font-bold uppercase tracking-wide">{report.report_type} Report</p>
                    <p className="text-xs text-muted-foreground truncate">
                      {new Date(report.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
                <a
                  href={`${API_BASE_URL}/jobs/${jobState.activeJob.id}/reports/${report.id}/download`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-2 bg-accent text-accent-foreground font-bold text-xs px-3 py-2 rounded-lg hover:brightness-110 transition-all active:scale-[0.97] shrink-0"
                >
                  <Download size={14} /> Download
                </a>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
