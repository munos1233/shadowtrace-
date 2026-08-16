import { useCallback, useEffect, useRef, useState } from "react";
import type { Action } from "../types/action";
import type {
  ConnectorPublic,
  DispositionResponse,
  EventDetailResponse,
  EventEvidenceResponse,
  ExecutionJobResponse,
  SourceRecordResponse,
  WritebackResponse,
} from "../types/event";
import type { AgentTrace } from "../types/trace";
import {
  getEvent,
  getEventEvidence,
  getExecutionJob,
  getSourceRecord,
  getTraces,
  getWriteback,
  listActions,
  listConnectors,
  listDispositions,
} from "../services/eventApi";
import { shouldFetchEventEvidence } from "../utils/evidenceContext";
import { socketClient } from "../services/socketClient";

type DetailResource =
  | "all"
  | "event"
  | "traces"
  | "actions"
  | "executionJobs"
  | "dispositions"
  | "writebacks";

/** Per-resource fetch success flags (ISSUE-206/207): callers like the report tab
 *  and inline approval flow must distinguish a refresh failure from success. */
export interface DetailRefreshResult {
  actionsOk: boolean;
  eventOk: boolean;
}

export interface EventWriteback extends WritebackResponse {
  provider_job_id?: string | null;
  provider_message?: string | null;
  submitted_at?: string | null;
  confirmed_at?: string | null;
  simulated?: boolean;
  sequence?: number;
}

function contextJobs(detail: EventDetailResponse | null): ExecutionJobResponse[] {
  const context = detail?.event.event_context_snapshot;
  return context?.execution_jobs ?? context?.execution_summary?.jobs ?? [];
}

function contextWritebacks(detail: EventDetailResponse | null): EventWriteback[] {
  return (detail?.event.event_context_snapshot?.disposition_receipts ?? []).map(
    (receipt) => ({
      writeback_id: receipt.writeback_id,
      disposition_id: receipt.disposition_id,
      action_id: receipt.action_id,
      status: receipt.status,
      confirmation_evidence: receipt.confirmation_evidence,
      evidence_tier: null,
      provider_code: receipt.provider_code ?? null,
      message_code: null,
      target_results: receipt.target_results ?? [],
      provider_job_id: receipt.provider_job_id,
      provider_message: receipt.provider_message,
      submitted_at: receipt.submitted_at,
      confirmed_at: receipt.confirmed_at,
      simulated: receipt.simulated,
      sequence: receipt.sequence,
    }),
  );
}

export function mergeWritebacks(
  contextItems: EventWriteback[],
  apiItems: WritebackResponse[],
): EventWriteback[] {
  const merged = new Map<string, EventWriteback>();
  for (const item of contextItems) {
    const existing = merged.get(item.writeback_id);
    if (!existing || (item.sequence ?? 0) >= (existing.sequence ?? 0)) {
      merged.set(item.writeback_id, item);
    }
  }
  for (const item of apiItems) {
    const existing = merged.get(item.writeback_id);
    merged.set(item.writeback_id, {
      ...existing,
      ...item,
      simulated: item.simulated ?? existing?.simulated ?? false,
    });
  }
  return [...merged.values()];
}

export function useEventDetail(eventId: string | undefined) {
  const [event, setEvent] = useState<EventDetailResponse | null>(null);
  const [traces, setTraces] = useState<AgentTrace[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [executionJobs, setExecutionJobs] = useState<ExecutionJobResponse[]>([]);
  const [dispositions, setDispositions] = useState<DispositionResponse[]>([]);
  const [writebacks, setWritebacks] = useState<EventWriteback[]>([]);
  const [sourceRecord, setSourceRecord] = useState<SourceRecordResponse | null>(null);
  const [connectors, setConnectors] = useState<ConnectorPublic[]>([]);
  const [evidenceDetail, setEvidenceDetail] = useState<EventEvidenceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const mountedRef = useRef(true);
  const eventRef = useRef<EventDetailResponse | null>(null);
  const actionsRef = useRef<Action[]>([]);

  eventRef.current = event;
  actionsRef.current = actions;

  const refresh = useCallback(
    async (resource: DetailResource = "all"): Promise<DetailRefreshResult> => {
      if (!eventId) {
        setLoading(false);
        return { actionsOk: false, eventOk: false };
      }
      const isAll = resource === "all";
      if (isAll) setLoading(true);

      const eventPromise =
        isAll || resource === "event" || resource === "writebacks"
          ? getEvent(eventId)
          : null;
      const tracesPromise = isAll || resource === "traces" ? getTraces(eventId) : null;
      const actionsPromise =
        isAll || resource === "actions" || resource === "executionJobs"
          ? listActions(eventId, { page: 1, page_size: 100 })
          : null;
      const dispositionsPromise =
        isAll || resource === "dispositions" || resource === "writebacks"
          ? listDispositions(eventId)
          : null;
      const connectorsPromise = isAll ? listConnectors() : null;

      const [eventResult, tracesResult, actionsResult, dispositionsResult, connectorsResult] =
        await Promise.allSettled([
          eventPromise,
          tracesPromise,
          actionsPromise,
          dispositionsPromise,
          connectorsPromise,
        ]);
      if (!mountedRef.current) return { actionsOk: false, eventOk: false };

      let actionsOk = false;
      let eventOk = false;
      let nextEvent = eventRef.current;
      if (eventResult.status === "fulfilled" && eventResult.value) {
        nextEvent = eventResult.value.data;
        eventRef.current = nextEvent;
        setEvent(nextEvent);
        eventOk = true;
      }
      if (tracesResult.status === "fulfilled" && tracesResult.value) {
        setTraces(tracesResult.value.data.items);
      }

      let nextActions = actionsRef.current;
      if (actionsResult.status === "fulfilled" && actionsResult.value) {
        nextActions = actionsResult.value.data.items;
        actionsRef.current = nextActions;
        setActions(nextActions);
        actionsOk = true;
      }
      if (dispositionsResult.status === "fulfilled" && dispositionsResult.value) {
        setDispositions(dispositionsResult.value.data.items);
      }
      if (connectorsResult.status === "fulfilled" && connectorsResult.value) {
        setConnectors(connectorsResult.value.data.items);
      }

      if ((isAll || resource === "event") && shouldFetchEventEvidence(nextEvent)) {
        try {
          const evidenceResult = await getEventEvidence(eventId);
          if (mountedRef.current) {
            setEvidenceDetail(evidenceResult.data);
          }
        } catch {
          if (mountedRef.current) {
            setEvidenceDetail(null);
          }
        }
      } else if (isAll || resource === "event") {
        setEvidenceDetail(null);
      }

      if (isAll && nextEvent?.event.current_primary_source_record_id) {
        void getSourceRecord(nextEvent.event.current_primary_source_record_id)
          .then((response) => {
            if (mountedRef.current) setSourceRecord(response.data);
          })
          .catch(() => undefined);
      }

      if (isAll || resource === "executionJobs" || resource === "actions") {
        const snapshotJobs = contextJobs(nextEvent);
        const jobIds = new Set(
          nextActions
            .map((action) => action.execution_job_id)
            .filter((id): id is string => Boolean(id)),
        );
        const fetched = await Promise.allSettled(
          [...jobIds].map((jobId) => getExecutionJob(jobId)),
        );
        if (mountedRef.current) {
          const apiJobs = fetched.flatMap((result) =>
            result.status === "fulfilled" ? [result.value.data] : [],
          );
          const byId = new Map(snapshotJobs.map((job) => [job.job_id, job]));
          for (const job of apiJobs) byId.set(job.job_id, { ...byId.get(job.job_id), ...job });
          setExecutionJobs([...byId.values()]);
        }
      }

      if (isAll || resource === "writebacks" || resource === "dispositions") {
        const snapshotWritebacks = contextWritebacks(nextEvent);
        const terminalId =
          nextEvent?.event.event_context_snapshot?.writeback_summary
            ?.terminal_event_writeback_id;
        const writebackIds = new Set(snapshotWritebacks.map((item) => item.writeback_id));
        if (terminalId) writebackIds.add(terminalId);
        const fetched = await Promise.allSettled(
          [...writebackIds].map((writebackId) => getWriteback(writebackId)),
        );
        if (mountedRef.current) {
          const apiWritebacks = fetched.flatMap((result) =>
            result.status === "fulfilled" ? [result.value.data] : [],
          );
          setWritebacks(mergeWritebacks(snapshotWritebacks, apiWritebacks));
        }
      }

      if (isAll && mountedRef.current) setLoading(false);
      return { actionsOk, eventOk };
    },
    [eventId],
  );

  useEffect(() => {
    mountedRef.current = true;
    void refresh("all");
    return () => {
      mountedRef.current = false;
    };
  }, [refresh]);

  useEffect(() => {
    if (!eventId) return;
    socketClient.connect();
    socketClient.subscribe(eventId);
    const unsubscribe = socketClient.onEvent((socketEvent) => {
      if (socketEvent.event_id !== eventId) return;
      if (
        socketEvent.type === "risk_updated" ||
        socketEvent.type === "state_change" ||
        socketEvent.type === "final_verdict_updated" ||
        socketEvent.type === "event_type_rewritten" ||
        socketEvent.type === "report_generated" ||
        socketEvent.type === "classification_updated"
      ) {
        void refresh("event");
      } else if (
        socketEvent.type === "action_executed" ||
        socketEvent.type === "action_verified" ||
        socketEvent.type === "approval_required" ||
        socketEvent.type === "approval_updated"
      ) {
        void refresh("actions");
        if (
          socketEvent.type === "approval_required" ||
          socketEvent.type === "approval_updated"
        ) {
          void refresh("event");
        }
      } else if (socketEvent.type === "disposition_submitted") {
        void refresh("dispositions");
      } else if (socketEvent.type === "writeback_updated") {
        void refresh("writebacks");
        void refresh("event");
      }
    });
    return unsubscribe;
  }, [eventId, refresh]);

  return {
    event,
    traces,
    actions,
    executionJobs,
    dispositions,
    writebacks,
    sourceRecord,
    connectors,
    evidenceDetail,
    loading,
    refresh,
  };
}
