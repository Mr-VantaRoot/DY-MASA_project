import { useLocation } from "wouter";
import { UploadCloud, ArrowRight, FileArchive, ShieldAlert } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { MetricCard } from "../components/MetricCard";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { StatusPill } from "../components/StatusPill";
import { useJobStateContext } from "../contexts/JobStateContext";

export function OverviewPage() {
  const jobState = useJobStateContext();
  const [, navigate] = useLocation();

  const totalJobs = jobState.jobs.length;
  const completedJobs = jobState.jobs.filter((j) => j.status === "completed");
  const runningJobs = jobState.jobs.filter((j) => j.status === "running");

  const severityCounts = jobState.findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>
  );

  let avgScanTime = "—";
  const finishedJobs = jobState.jobs.filter((j) => j.completed_at);
  if (finishedJobs.length > 0) {
    const totalSecs = finishedJobs.reduce((sum, job) => {
      const start = new Date(job.created_at).getTime();
      const end = new Date(job.completed_at!).getTime();
      return sum + Math.max(0, (end - start) / 1000);
    }, 0);
    avgScanTime = `${Math.round(totalSecs / finishedJobs.length)}s`;
  }

  return (
    <AppShell title="Overview" subtitle="Fleet-wide APK security posture at a glance">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Total Scans" value={totalJobs} accent="neutral" />
        <MetricCard label="Completed" value={completedJobs.length} accent="info" />
        <MetricCard label="Running" value={runningJobs.length} accent="medium" />
        <MetricCard label="Avg Scan Time" value={avgScanTime} accent="neutral" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1 bg-card border border-border rounded-xl p-6">
          <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-4">
            Severity Distribution
          </h3>
          {jobState.findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <ShieldAlert size={36} className="mb-3 opacity-40" />
              <p className="text-sm">No findings yet for the active job.</p>
            </div>
          ) : (
            <SeverityDonut counts={severityCounts} />
          )}
        </div>

        <div className="xl:col-span-2 bg-card border border-border rounded-xl p-6 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-wide">Recent Jobs</h3>
            <button
              onClick={() => navigate("/jobs")}
              className="text-xs font-bold text-accent flex items-center gap-1 hover:underline"
            >
              View all <ArrowRight size={12} />
            </button>
          </div>
          {jobState.jobs.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-8 text-muted-foreground">
              <FileArchive size={36} className="mb-3 opacity-40" />
              <p className="text-sm mb-4">No scans yet. Upload an APK to get started.</p>
              <button
                onClick={() => navigate("/scan")}
                className="flex items-center gap-2 bg-accent text-accent-foreground font-bold px-4 py-2 rounded-lg text-sm hover:brightness-110"
              >
                <UploadCloud size={16} /> Start a scan
              </button>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {jobState.jobs.slice(0, 6).map((job) => (
                <button
                  key={job.id}
                  onClick={() => {
                    jobState.setSelectedJobId(job.id);
                    navigate("/findings");
                  }}
                  className="flex items-center justify-between p-3 rounded-lg hover:bg-secondary/50 transition-colors text-left border border-transparent hover:border-border"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <FileArchive size={16} className="text-muted-foreground shrink-0" />
                    <span className="text-sm font-semibold truncate">{job.original_filename}</span>
                  </div>
                  <StatusPill status={job.status} />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="bg-gradient-to-r from-accent/10 to-transparent border border-accent/20 rounded-xl p-6 flex items-center justify-between flex-wrap gap-4">
        <div>
          <h3 className="text-lg font-bold mb-1">Ready to assess another APK?</h3>
          <p className="text-sm text-muted-foreground">
            Real apktool + JADX decompilation, evidence-backed findings, and exportable reports.
          </p>
        </div>
        <button
          onClick={() => navigate("/scan")}
          className="flex items-center gap-2 bg-accent text-accent-foreground font-bold px-5 py-3 rounded-lg hover:brightness-110 active:scale-[0.97] transition-all"
        >
          <UploadCloud size={18} /> New Scan
        </button>
      </div>
    </AppShell>
  );
}
