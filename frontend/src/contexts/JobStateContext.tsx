import { createContext, useContext, type ReactNode } from "react";
import { useJobState } from "../hooks/useJobState";

type JobStateValue = ReturnType<typeof useJobState>;

const JobStateContext = createContext<JobStateValue | null>(null);

export function JobStateProvider({ children }: { children: ReactNode }) {
  const state = useJobState();
  return <JobStateContext.Provider value={state}>{children}</JobStateContext.Provider>;
}

export function useJobStateContext(): JobStateValue {
  const ctx = useContext(JobStateContext);
  if (!ctx) throw new Error("useJobStateContext must be used within JobStateProvider");
  return ctx;
}
