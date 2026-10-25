export type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AnalysisJob = {
  id: string;
  original_filename: string;
  file_size_bytes: number;
  sha256: string | null;
  ghidra_enabled: boolean;
  status: JobStatus;
  progress: number;
  current_step: string;
  error_message: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
};

export type EvidenceItem = {
  id: string;
  category: string;
  evidence_type: string;
  label: string;
  value_json: string;
  source_path?: string;
};

export type ArtifactItem = {
  id: string;
  job_id: string;
  artifact_type: string;
  tool_name: string;
  path: string;
  exit_code: number | null;
  created_at: string;
};

export type FindingItem = {
  id: string;
  job_id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  remediation: string;
  evidence_ids_json: string;
};

export type ReasoningItem = {
  id: string;
  provider: string;
  summary: string;
  attack_paths_json: string;
  limitations: string;
};

export type ReportItem = {
  id: string;
  report_type: string;
  path: string;
  created_at: string;
};

export type TimelineEntry = {
  id: string;
  job_id: string;
  stage: string;
  status: string;
  message: string;
  detail: string | null;
  created_at: string;
};

export type PipelineEvent = {
  event_id: number;
  stage: string;
  status: string;
  message: string;
  detail: string | null;
  timestamp: string;
};
