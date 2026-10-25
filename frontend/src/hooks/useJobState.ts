import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { API_BASE_URL, deleteJob } from "../lib/api";
import type { AnalysisJob, EvidenceItem, FindingItem, ReasoningItem, ReportItem, TimelineEntry, PipelineEvent } from "../types";

export function useJobState() {
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [reasoning, setReasoning] = useState<ReasoningItem | null>(null);
  const [reasoningRecords, setReasoningRecords] = useState<ReasoningItem[]>([]);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [pipelineEvents, setPipelineEvents] = useState<PipelineEvent[]>([]);
  const [liveLog, setLiveLog] = useState<string[]>([]);
  const [selectedJobId, setSelectedJobIdState] = useState<string | null>(null);
  const detailRequestRef = useRef(0);
  const [error, setError] = useState<string | null>(null);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);

  const activeJob = useMemo(() => jobs.find((job) => job.id === selectedJobId) ?? jobs[0] ?? null, [jobs, selectedJobId]);
  const activeJobId = activeJob?.id ?? null;

  const clearJobDetails = useCallback(() => {
    setEvidence([]);
    setFindings([]);
    setReasoning(null);
    setReasoningRecords([]);
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
    const requestId = ++detailRequestRef.current;
    try {
      const responses = await Promise.all([
        fetch(`${API_BASE_URL}/jobs/${jobId}/evidence`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/findings`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/reasoning`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/reports`),
        fetch(`${API_BASE_URL}/jobs/${jobId}/timeline`),
      ]);
      const payloads = await Promise.all(responses.map((response) => response.ok ? response.json() : Promise.resolve(null)));
      if (requestId !== detailRequestRef.current) return;
      const [evidencePayload, findingsPayload, reasoningPayload, reportsPayload, timelinePayload] = payloads;
      const records = Array.isArray(reasoningPayload?.reasoning) ? reasoningPayload.reasoning : [];
      setEvidence(Array.isArray(evidencePayload?.evidence) ? evidencePayload.evidence : []);
      setFindings(Array.isArray(findingsPayload?.findings) ? findingsPayload.findings : []);
      setReasoningRecords(records);
      // A job may receive a refreshed reasoning record after dynamic analysis;
      // the newest persisted record is the authoritative summary.
      setReasoning(records.at(-1) ?? null);
      setReports(Array.isArray(reportsPayload?.reports) ? reportsPayload.reports : []);
      setTimeline(Array.isArray(timelinePayload?.stages) ? timelinePayload.stages : []);
      if (responses.some((response) => !response.ok)) setError("Some records could not be loaded for this scan");
      else setError(null);
    } catch (e) {
      if (requestId !== detailRequestRef.current) return;
      clearJobDetails();
      setError("Scan details could not be loaded");
    }
  }, [clearJobDetails]);

  const setSelectedJobId = useCallback((jobId: string | null) => {
    detailRequestRef.current += 1;
    clearJobDetails();
    setSelectedJobIdState(jobId);
  }, [clearJobDetails]);

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
    reasoningRecords,
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
