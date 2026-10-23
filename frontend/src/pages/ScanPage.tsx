import { useState } from "react";
import { useLocation } from "wouter";
import { AppShell } from "../components/layout/AppShell";
import { UploadPanel } from "../components/UploadPanel";
import { JobStatusPanel } from "../components/JobStatusPanel";
import { PipelineTimeline } from "../components/PipelineTimeline";
import { LiveLog } from "../components/LiveLog";
import { useJobStateContext } from "../contexts/JobStateContext";

export function ScanPage() {
  const jobState = useJobStateContext();
  const [, navigate] = useLocation();
  const [isDropping, setIsDropping] = useState(false);

  async function dropActiveAnalysis() {
    if (!jobState.activeJob || isDropping) return;
    setIsDropping(true);
    try {
      await jobState.dropJob(jobState.activeJob.id);
      navigate("/");
    } finally {
      setIsDropping(false);
    }
  }

  return (
    <AppShell title="Scan" subtitle="Upload an APK and watch the pipeline run live">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 md:gap-8">
        <div className="xl:col-span-1 bg-card border border-border rounded-xl overflow-hidden">
          <UploadPanel
            onUploadComplete={(id) => {
              jobState.setSelectedJobId(id);
              jobState.loadJobs();
            }}
          />
        </div>
        <div className="xl:col-span-2">
          <JobStatusPanel
            activeJob={jobState.activeJob}
            evidenceCount={jobState.evidence.length}
            findingsCount={jobState.findings.length}
            onDropAnalysis={dropActiveAnalysis}
            isDropping={isDropping}
          />
        </div>
      </div>

      <PipelineTimeline
        timeline={jobState.timeline}
        pipelineEvents={jobState.pipelineEvents}
        activeJob={jobState.activeJob}
      />

      <LiveLog
        liveLog={jobState.liveLog}
        activeJob={jobState.activeJob}
      />
    </AppShell>
  );
}
