import { useLocation } from "wouter";
import { FileArchive } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { StatusPill } from "../components/StatusPill";
import { useJobStateContext } from "../contexts/JobStateContext";

export function JobsPage() {
  const jobState = useJobStateContext();
  const [, navigate] = useLocation();

  return (
    <AppShell title="Job History" subtitle={`${jobState.jobs.length} total scans on this instance`}>
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {jobState.jobs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <FileArchive size={48} className="mb-4 opacity-40" />
            <p className="text-lg font-semibold">No scans yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="px-6 py-3 text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
                    File
                  </th>
                  <th className="px-6 py-3 text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
                    Size
                  </th>
                  <th className="px-6 py-3 text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
                    Started
                  </th>
                  <th className="px-6 py-3 text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
                    Completed
                  </th>
                </tr>
              </thead>
              <tbody>
                {jobState.jobs.map((job) => (
                  <tr
                    key={job.id}
                    onClick={() => {
                      jobState.setSelectedJobId(job.id);
                      navigate("/findings");
                    }}
                    className="border-b border-border/50 hover:bg-secondary/40 cursor-pointer transition-colors"
                  >
                    <td className="px-6 py-3 font-semibold truncate max-w-[280px]">{job.original_filename}</td>
                    <td className="px-6 py-3">
                      <StatusPill status={job.status} />
                    </td>
                    <td className="px-6 py-3 font-mono text-xs text-muted-foreground">
                      {(job.file_size_bytes / (1024 * 1024)).toFixed(1)} MB
                    </td>
                    <td className="px-6 py-3 text-xs text-muted-foreground">
                      {new Date(job.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 text-xs text-muted-foreground">
                      {job.completed_at ? new Date(job.completed_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AppShell>
  );
}
