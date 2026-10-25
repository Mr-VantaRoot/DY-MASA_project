const configuredApiBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim();

/** Default directly to the local FastAPI backend unless an environment override is provided. */
export const API_BASE_URL =
  configuredApiBase && configuredApiBase.length > 0
    ? configuredApiBase.replace(/\/$/, "")
    : "http://127.0.0.1:8000/api";

const terminalToken = (import.meta.env.VITE_TERMINAL_TOKEN as string | undefined)?.trim();

export function formatApiError(error: unknown, fallback: string): string {
  if (error instanceof TypeError) {
    return "Cannot reach the backend API. Start the backend on http://127.0.0.1:8000 and confirm /api/health responds.";
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

export const PIPELINE_STEPS = [
  { key: "upload_received", label: "Upload received" },
  { key: "workspace_created", label: "Workspace created" },
  { key: "sha256_computed", label: "SHA-256 computed" },
  { key: "apktool_decode", label: "apktool decode" },
  { key: "jadx_decompile", label: "JADX decompile" },
  { key: "ghidra_analysis", label: "Ghidra native analysis" },
  { key: "evidence_extraction", label: "Evidence extraction" },
  { key: "rule_analysis", label: "Rule analysis" },
  { key: "report_generation", label: "Report generation" },
] as const;

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const SEVERITY_LABELS = ["critical", "high", "medium", "low", "info"] as const;

export const SEVERITY_HEX: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

export const EVIDENCE_CATEGORY_LABELS: Record<string, string> = {
  manifest: "Manifest Metadata",
  permission: "Permissions",
  component: "Exported Components",
  deep_link: "Deep Links",
  application_flag: "Application Flags",
  code_secret: "Hardcoded Secret Candidates",
  code_risk: "Code-Level Risk Patterns",
  runtime: "Dynamic Runtime Evidence",
};

export async function fetchHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) throw new Error("Unable to reach backend health endpoint.");
  return response.json();
}

export async function runTerminalCommand(command: string, cwd?: string, previousCwd?: string) {
  const response = await fetch(`${API_BASE_URL}/terminal/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(terminalToken ? { "X-Terminal-Token": terminalToken } : {}),
    },
    body: JSON.stringify({ command, cwd, previous_cwd: previousCwd }),
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 404) throw new Error("Terminal is disabled. Set MOBILE_PENTEST_ENABLE_TERMINAL=true and configure MOBILE_PENTEST_TERMINAL_TOKEN to enable it.");
  if (!response.ok) throw new Error(payload.detail ?? "Terminal command failed.");
  return payload as { command: string; cwd: string; output: string; exit_code: number };
}



export async function deleteJob(jobId: string, keepalive = false) {
  const response = await fetch(`${API_BASE_URL}/jobs/${jobId}`, { method: "DELETE", keepalive });
  if (!response.ok && response.status !== 404) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail ?? "Unable to drop analysis job.");
  }
}


export type DynamicStatus = {
  adb_available: boolean;
  emulator_available: boolean;
  avd_name: string | null;
  avd_available: boolean;
  devices: { serial: string; state: string }[];
  ready_device: string | null;
  android_version: string | null;
  device_model: string | null;
  sdk_path: string;
  adb_path: string;
  emulator_path: string;
};

export type DynamicStorage = {
  device: string;
  storage: {
    path: string;
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    used_percent: number;
    is_full: boolean;
  };
  categories: { video_bytes: number; image_bytes: number; other_bytes: number };
  scanned_paths: string[];
  detail: string | null;
  read_only: boolean;
};

export async function fetchDynamicStatus() {
  const response = await fetch(`${API_BASE_URL}/dynamic/status`);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail ?? "Unable to load DY-MASA status.");
  return payload as DynamicStatus;
}

export async function fetchDynamicStorage() {
  const response = await fetch(`${API_BASE_URL}/dynamic/storage`);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail ?? "Unable to read device storage.");
  return payload as DynamicStorage;
}

export async function startDynamicAnalysis(jobId: string) {
  const response = await fetch(`${API_BASE_URL}/jobs/${jobId}/dynamic/start`, { method: "POST" });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail ?? "Unable to start DY-MASA.");
  return payload as { status: string; job_id: string };
}

export async function fetchDynamicEvents(jobId: string) {
  const response = await fetch(`${API_BASE_URL}/jobs/${jobId}/dynamic/events`);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail ?? "Unable to load DY-MASA events.");
  return payload.stages ?? [];
}

export async function fetchDynamicEvidence(jobId: string) {
  const response = await fetch(`${API_BASE_URL}/jobs/${jobId}/dynamic/evidence`);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail ?? "Unable to load DY-MASA evidence.");
  return payload.evidence ?? [];
}

export async function fetchDynamicArtifacts(jobId: string) {
  const response = await fetch(`${API_BASE_URL}/jobs/${jobId}/artifacts`);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail ?? "Unable to load DY-MASA artifacts.");
  return payload.artifacts ?? [];
}
