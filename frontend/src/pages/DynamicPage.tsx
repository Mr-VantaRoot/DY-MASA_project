import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Activity, Download, FileJson, HardDrive, Image, Play, RefreshCw, Smartphone, TerminalSquare } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { StatusPill } from "../components/StatusPill";
import { useJobStateContext } from "../contexts/JobStateContext";
import { API_BASE_URL, fetchDynamicArtifacts, fetchDynamicEvidence, fetchDynamicEvents, fetchDynamicStatus, fetchDynamicStorage, startDynamicAnalysis, type DynamicStatus, type DynamicStorage } from "../lib/api";
import type { ArtifactItem, EvidenceItem, TimelineEntry } from "../types";

export function DynamicPage() {
  const jobState = useJobStateContext();
  const [status, setStatus] = useState<DynamicStatus | null>(null);
  const [storage, setStorage] = useState<DynamicStorage | null>(null);
  const [storageError, setStorageError] = useState<string | null>(null);
  const [events, setEvents] = useState<TimelineEntry[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactItem[]>([]);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const activeJob = jobState.activeJob;
  // A physical ADB device is a supported runtime target; an emulator is optional.
  const dynamicReady = Boolean(status?.adb_available && status?.ready_device);
  const latestEvent = events[events.length - 1];
  const dynamicRun = [...events].reverse().find((event) => event.stage === "dynamic_run");

  async function refreshDynamicState() {
    try {
      const nextStatus = await fetchDynamicStatus();
      setStatus(nextStatus);
      setError(null);
      if (activeJob) {
        const [nextEvents, nextEvidence, nextArtifacts] = await Promise.all([
          fetchDynamicEvents(activeJob.id),
          fetchDynamicEvidence(activeJob.id),
          fetchDynamicArtifacts(activeJob.id),
        ]);
        setEvents(nextEvents);
        setEvidence(nextEvidence);
        setArtifacts(nextArtifacts.filter((artifact: ArtifactItem) => artifact.artifact_type === "dynamic_artifact"));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load DY-MASA state.");
    }
  }

  async function startRuntimeRun() {
    if (!activeJob || isStarting) return;
    setIsStarting(true);
    setError(null);
    try {
      await startDynamicAnalysis(activeJob.id);
      await refreshDynamicState();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start DY-MASA.");
    } finally {
      setIsStarting(false);
    }
  }

  useEffect(() => {
    refreshDynamicState();
    const id = window.setInterval(refreshDynamicState, 3000);
    return () => window.clearInterval(id);
  }, [activeJob?.id]);

  useEffect(() => {
    if (!status?.ready_device) {
      setStorage(null);
      return;
    }
    const refreshStorage = async () => {
      try {
        setStorage(await fetchDynamicStorage());
        setStorageError(null);
      } catch (err) {
        setStorageError(err instanceof Error ? err.message : "Unable to read device storage.");
      }
    };
    refreshStorage();
    const id = window.setInterval(refreshStorage, 15000);
    return () => window.clearInterval(id);
  }, [status?.ready_device]);

  const logLines = useMemo(() => {
    return events.map((event) => {
      const time = new Date(event.created_at).toLocaleTimeString();
      return `[${time}] ${event.stage} ${event.status}: ${event.message}${event.detail ? ` - ${event.detail}` : ""}`;
    });
  }, [events]);

  return (
    <AppShell title="DY-MASA" subtitle="Dynamic Android runtime lab for emulator-based validation">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide">Runtime Status</h2>
            <button onClick={refreshDynamicState} className="text-accent hover:text-foreground" title="Refresh status">
              <RefreshCw size={16} />
            </button>
          </div>
          <div className="space-y-3 text-sm">
            <StatusRow label="ADB" ok={Boolean(status?.adb_available)} value={status?.adb_path || "Not checked"} />
            <StatusRow label="Emulator (optional)" ok={Boolean(status?.emulator_available)} value={status?.emulator_path || "Not configured"} />
            <StatusRow label="AVD" ok={Boolean(status?.avd_available)} value={status?.avd_name || "Not configured"} />
            <StatusRow label="Device" ok={Boolean(status?.ready_device)} value={status?.ready_device || "No ready device"} />
            <StatusRow label="Android version" ok={Boolean(status?.android_version)} value={status?.android_version ? `Android ${status.android_version}` : "Unknown"} />
            <StatusRow label="Model" ok={Boolean(status?.device_model)} value={status?.device_model || "Unknown"} />
          </div>
        </div>

        <div className="xl:col-span-2 bg-card border border-border rounded-xl p-5">
          <div className="flex items-start justify-between gap-4 mb-4">
            <div>
              <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">Active APK</h2>
              {activeJob ? (
                <div>
                  <p className="text-lg font-bold break-all">{activeJob.original_filename}</p>
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase">Static scan</span>
                    <StatusPill status={activeJob.status} />
                    <span className="text-xs font-semibold text-muted-foreground uppercase ml-2">DY-MASA</span>
                    {dynamicRun ? <StatusPill status={dynamicRun.status as "queued" | "running" | "completed" | "failed" | "cancelled"} /> : <span className="text-xs text-muted-foreground">Not started</span>}
                  </div>
                </div>
              ) : (
                <p className="text-muted-foreground">Select or complete a static scan first.</p>
              )}
            </div>
            <button
              onClick={startRuntimeRun}
              disabled={!activeJob || !dynamicReady || isStarting}
              className="inline-flex items-center gap-2 bg-accent text-accent-foreground font-bold px-4 py-2 rounded-lg disabled:opacity-50 disabled:pointer-events-none hover:brightness-110"
            >
              <Play size={16} /> {isStarting ? "Starting..." : "Start Dynamic Run"}
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Metric icon={<Smartphone size={16} />} label="Devices" value={status?.devices.length ?? 0} />
            <Metric icon={<Activity size={16} />} label="Runtime Events" value={events.length} />
            <Metric icon={<TerminalSquare size={16} />} label="Runtime Evidence" value={evidence.length} />
          </div>
          {latestEvent && (
            <p className="mt-4 text-sm text-muted-foreground">
              Latest: <span className="text-foreground font-semibold">{latestEvent.message}</span>{latestEvent.detail ? ` - ${latestEvent.detail}` : ""}
            </p>
          )}
          {error && <p className="mt-4 text-sm text-critical font-semibold">{error}</p>}
          {!dynamicReady && !error && (
            <p className="mt-4 text-sm text-muted-foreground">DY-MASA is waiting for ADB to see a ready emulator/device.</p>
          )}
        </div>
      </div>

      <div className="mt-6 bg-card border border-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide">Device Storage</h2>
            <p className="text-xs text-muted-foreground mt-1">Read-only estimate from shared Android storage</p>
          </div>
          <HardDrive size={18} className="text-accent" />
        </div>
        {!storage && !storageError && <p className="text-sm text-muted-foreground">Connect an authorized device to inspect storage.</p>}
        {storageError && <p className="text-sm text-critical font-semibold">{storageError}</p>}
        {storage && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <StorageMetric label="Capacity" value={formatBytes(storage.storage.total_bytes)} />
              <StorageMetric label="Used" value={`${formatBytes(storage.storage.used_bytes)} (${storage.storage.used_percent.toFixed(1)}%)`} />
              <StorageMetric label="Free" value={formatBytes(storage.storage.available_bytes)} critical={storage.storage.is_full} />
              <StorageMetric label="Status" value={storage.storage.is_full ? "Nearly full" : "Available"} critical={storage.storage.is_full} />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <StorageMetric label="Video estimate" value={formatBytes(storage.categories.video_bytes)} />
              <StorageMetric label="Images estimate" value={formatBytes(storage.categories.image_bytes)} />
              <StorageMetric label="Other files" value={formatBytes(storage.categories.other_bytes)} />
            </div>
            <p className="text-xs text-muted-foreground">Scanned common folders only; no file contents were opened or changed. Estimates may include mixed media in DCIM.</p>
          </div>
        )}
      </div>

      <div className="mt-6 grid grid-cols-1 xl:grid-cols-2 gap-6 xl:h-[clamp(320px,45vh,480px)] xl:items-stretch">
        <div className="bg-card border border-border rounded-xl p-5 flex min-h-0 flex-col">
          <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-4">Runtime Evidence</h2>
          {evidence.length === 0 ? <p className="text-sm text-muted-foreground">Runtime evidence will appear after DY-MASA completes.</p> : (
            <div className="min-h-0 flex-1 space-y-3 overflow-y-auto">
              {evidence.map((item) => <details key={item.id} className="border border-border rounded-lg p-3">
                <summary className="cursor-pointer text-sm font-semibold">{item.label}</summary>
                <p className="text-xs text-muted-foreground mt-2">{item.evidence_type}</p>
                <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded bg-[#060a0d] p-3 text-xs">{prettyJson(item.value_json)}</pre>
              </details>)}
            </div>
          )}
        </div>

        <div className="bg-card border border-border rounded-xl p-5 flex min-h-0 flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide">Runtime Artifacts</h2>
            {activeJob && <a href="/reports" className="text-xs text-accent hover:underline">Open reports</a>}
          </div>
          {artifacts.length === 0 ? <p className="text-sm text-muted-foreground">Logs, screenshots, and validation files will appear after a run.</p> : (
            <div className="min-h-0 flex-1 space-y-3 overflow-y-auto">
              {artifacts.map((artifact) => {
                const image = artifact.path.toLowerCase().endsWith(".png");
                return <div key={artifact.id} className="flex items-center justify-between gap-3 border border-border rounded-lg p-3">
                  <div className="flex items-center gap-3 min-w-0">
                    {image ? <Image size={18} className="text-accent shrink-0" /> : <FileJson size={18} className="text-accent shrink-0" />}
                    <div className="min-w-0"><p className="text-sm font-semibold">{artifact.tool_name}</p><p className="text-xs text-muted-foreground truncate">{artifact.path.split("/").pop()}</p></div>
                  </div>
                  <a href={`${API_BASE_URL}/jobs/${artifact.job_id}/artifacts/${artifact.id}/view`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded bg-accent px-3 py-2 text-xs font-bold text-accent-foreground shrink-0"><Download size={13} /> View</a>
                </div>;
              })}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="p-4 border-b border-border">
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide">Dynamic Events</h2>
          </div>
          <div className="p-4 space-y-3 max-h-[420px] overflow-y-auto">
            {events.length === 0 ? <p className="text-sm text-muted-foreground">No dynamic run events yet.</p> : events.map((event) => (
              <div key={event.id} className="border border-border rounded-lg p-3">
                <p className="text-sm font-bold">{event.message}</p>
                <p className="text-xs text-muted-foreground mt-1">{event.stage} / {event.status}</p>
                {event.detail && <p className="text-xs mt-2 break-all">{event.detail}</p>}
              </div>
            ))}
          </div>
        </div>

        <div className="bg-[#060a0d] border border-border rounded-xl overflow-hidden flex flex-col h-[480px]">
          <div className="p-4 border-b border-[#1e2a35] bg-[#0a0e13]">
            <h2 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Live Dynamic Output</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4 font-mono text-[0.78rem] leading-relaxed">
            {logLines.length === 0 ? <p className="text-[#00d4aa]/50 italic">Waiting for DY-MASA runtime output...</p> : logLines.map((line, index) => (
              <p key={index} className="text-[#dbe7ea] break-all py-0.5">{line}</p>
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  );
}

function StatusRow({ label, ok, value }: { label: string; ok: boolean; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border/60 pb-2 last:border-b-0">
      <span className="font-semibold text-muted-foreground">{label}</span>
      <span className={`text-right break-all ${ok ? "text-accent" : "text-critical"}`}>{value}</span>
    </div>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: number }) {
  return (
    <div className="border border-border rounded-lg p-3 bg-secondary/30">
      <div className="flex items-center gap-2 text-muted-foreground text-xs uppercase font-bold">{icon}{label}</div>
      <p className="text-2xl font-bold mt-2">{value}</p>
    </div>
  );
}

function StorageMetric({ label, value, critical = false }: { label: string; value: string; critical?: boolean }) {
  return <div className="border border-border rounded-lg p-3 bg-secondary/30">
    <p className="text-xs uppercase font-bold text-muted-foreground">{label}</p>
    <p className={`text-lg font-bold mt-2 ${critical ? "text-critical" : "text-foreground"}`}>{value}</p>
  </div>;
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
}

function prettyJson(value: string) {
  try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
}
