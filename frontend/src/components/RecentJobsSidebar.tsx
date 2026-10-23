import { FileArchive } from "lucide-react";
import type { AnalysisJob } from "../types";

export function RecentJobsSidebar({ jobs, activeJobId, onSelectJob }: { jobs: AnalysisJob[], activeJobId?: string, onSelectJob: (id: string) => void }) {
  return (
    <div className="flex-1 overflow-y-auto p-5 border-t border-border flex flex-col">
      <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-4">Recent Jobs</h2>
      <div className="flex flex-col gap-2">
        {jobs.length === 0 ? (
          <p className="text-muted-foreground text-sm">No jobs yet.</p>
        ) : (
          jobs.slice(0, 15).map(job => (
            <button
              key={job.id}
              onClick={() => onSelectJob(job.id)}
              className={`flex items-start gap-3 p-3 rounded-md text-left transition-all duration-150 border-l-2 ${activeJobId === job.id ? 'bg-secondary border-accent' : 'border-transparent hover:bg-secondary/50 hover:border-muted-foreground'}`}
            >
              <FileArchive size={16} className={`mt-0.5 shrink-0 ${activeJobId === job.id ? 'text-accent' : 'text-muted-foreground'}`} />
              <div className="flex flex-col overflow-hidden w-full">
                <span className="text-sm font-semibold truncate text-foreground">{job.original_filename}</span>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${job.status === 'completed' ? 'bg-[#00d4aa]' : job.status === 'failed' ? 'bg-critical' : job.status === 'running' ? 'bg-low animate-pulse' : 'bg-gray-500'}`} />
                  <span className="text-xs text-muted-foreground capitalize">{job.status}</span>
                </div>
              </div>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
