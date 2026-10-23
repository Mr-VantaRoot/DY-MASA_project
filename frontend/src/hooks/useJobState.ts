import { useState, useEffect, useMemo, useCallback } from "react";
import { API_BASE_URL, deleteJob } from "../lib/api";
import type { AnalysisJob, EvidenceItem, FindingItem, ReasoningItem, ReportItem, TimelineEntry, PipelineEvent } from "../types";

export function useJobState() {
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [reasoning, setReasoning] = useState<ReasoningItem | null>(null);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [pipelineEvents, setPipelineEvents] = useState<PipelineEvent[]>([]);
  const [liveLog, setLiveLog] = useState<string[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);

  const activeJob = useMemo(() => jobs.find((job) => job.id === selectedJobId) ?? jobs[0] ?? null, [jobs, selectedJobId]);
  const activeJobId = activeJob?.id ?? null;

  const clearJobDetails = useCallback(() => {
    setEvidence([]);
    setFindings([]);
    setReasoning(null);
    setReports([]);
    setTimeline([]);
    setPipelineEvents([]);
    setLiveLog([]);
  }, []);

  const loadJobs = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/jobs`);
      if (!response.ok) throw new Error("Backend is not reachable");
      const payload = await response.json();
      setJobs(payload.jobs);
      setIsBackendConnected(true);
      setError(null);
      return payload.jobs as AnalysisJob[];
    } catch (err) {
      setIsBackendConnected(false);
      setError("Backend is not reachable");
      return [];
    }
  }, []);

  const loadJobDetails = useCallback(async (jobId: string) => {
    try {
      const [evidenceRes, findingsRes, reasoningRes, reportsRes, timelineRes] = await Promise.all([
        fetch(`${API_BASE_URL}/jobs/${jobId}/evidence`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/findings`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/reasoning`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/reports`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/timeline`),
      ]);

      if (evidenceRes.ok) setEvidence((await evidenceRes.json()).evidence);
      if (findingsRes.ok) setFindings((await findingsRes.json()).findings);
      if (reasoningRes.ok) setReasoning((await reasoningRes.json()).reasoning[0] ?? null);
      if (reportsRes.ok) setReports((await reportsRes.json()).reports);
      if (timelineRes.ok) setTimeline((await timelineRes.json()).stages);
    } catch (e) {
      // Polling failures are reflected by the backend status indicator.
    }
  }, []);

  const dropJob = useCallback(async (jobId?: string, keepalive = false) => {
    const targetJobId = jobId ?? activeJobId;
    if (!targetJobId) return;
    await deleteJob(targetJobId, keepalive);
    setJobs((current) => current.filter((job) => job.id !== targetJobId));
    if (selectedJobId === targetJobId || activeJobId === targetJobId) {
      setSelectedJobId(null);
      clearJobDetails();
    }
  }, [activeJobId, clearJobDetails, selectedJobId]);

  useEffect(() => {
    loadJobs();
    const intervalId = window.setInterval(() => {
      loadJobs().catch(() => undefined);
      if (activeJobId) loadJobDetails(activeJobId).catch(() => undefined);
    }, 2500);
    return () => window.clearInterval(intervalId);
  }, [activeJobId, loadJobs, loadJobDetails]);

  useEffect(() => {
    if (!activeJobId) {
      clearJobDetails();
      return;
    }

    setPipelineEvents([]);
    setLiveLog([]);
    loadJobDetails(activeJobId).catch(() => undefined);

    const source = new EventSource(`${API_BASE_URL}/jobs/${activeJobId}/events`);
    source.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as PipelineEvent;
        const message = payload.message?.trim();
        const detail = payload.detail?.trim();
        const timestamp = payload.timestamp ? `[${payload.timestamp.slice(11, 19)}]` : ">";
        const line = [message, detail].filter(Boolean).join(" - ");
        setPipelineEvents((current) => [...current, payload]);
        if (line) setLiveLog((current) => [...current, `${timestamp} ${line}`]);
        if (["job_completed", "job_failed", "job_cancelled"].includes(payload.stage)) {
          source.close();
        }
      } catch (e) {
        // Ignore malformed SSE payloads.
      }
    };
    // Leave the source open on transient failures so EventSource can reconnect
    // with Last-Event-ID and recover durable events from the backend.

    return () => source.close();
  }, [activeJobId, clearJobDetails, loadJobDetails]);

  useEffect(() => {
    if (!activeJobId || !activeJob || !["queued", "running"].includes(activeJob.status)) return;
    const dropOnUnload = () => {
      fetch(`${API_BASE_URL}/jobs/${activeJobId}`, { method: "DELETE", keepalive: true }).catch(() => undefined);
    };
    window.addEventListener("beforeunload", dropOnUnload);
    return () => window.removeEventListener("beforeunload", dropOnUnload);
  }, [activeJob, activeJobId]);

  return {
    jobs,
    evidence,
    findings,
    reasoning,
    reports,
    timeline,
    pipelineEvents,
    liveLog,
    activeJob,
    selectedJobId,
    setSelectedJobId,
    loadJobs,
    loadJobDetails,
    dropJob,
    error,
    isBackendConnected
  };
}
