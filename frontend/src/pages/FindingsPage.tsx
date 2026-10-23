import { AppShell } from "../components/layout/AppShell";
import { FindingsList } from "../components/FindingsList";
import { useJobStateContext } from "../contexts/JobStateContext";

export function FindingsPage() {
  const jobState = useJobStateContext();

  return (
    <AppShell
      title="Findings"
      subtitle={jobState.activeJob ? `Evidence-backed triage for ${jobState.activeJob.original_filename}` : "No active job"}
    >
      <FindingsList findings={jobState.findings} />
    </AppShell>
  );
}
