/** Approval store — pending approvals with socket-driven updates (ISSUE-073). */

import { create } from "zustand";
import { notification } from "antd";
import type { Action, ActionOperationResponse } from "../types/action";
import {
  listActions,
  listEvents,
  approveAction,
  rejectAction,
} from "../services/eventApi";
import { socketClient } from "../services/socketClient";
import type { SocketEvent } from "../types/socket";

export interface ApprovalDecisionBody {
  comment?: string;
  decision_id: string;
}

/** Outcome of a queue (re)load — distinguishes total/partial success (ISSUE-207 review). */
export type QueueRefreshResult = "ok" | "partial" | "failed";

interface ApprovalState {
  /** Global queue across all events (global listener + polling). */
  pendingApprovals: Action[];
  loading: boolean;
  error: string | null;
  unreadCount: number;
  /** action_id -> ISO deadline from approval_required socket payload. */
  approvalDeadlines: Record<string, string>;
  /** Deep-link scoped queue (?event_id=) — isolated from the global queue so
   *  polling / the global listener can never overwrite it (ISSUE-207 review). */
  eventPendingApprovals: Action[];
  /** Scoped loading/error — isolated from the global loading/error so a fast
   *  global poll cannot end the scoped spinner early or leak scoped errors. */
  eventLoading: boolean;
  eventError: string | null;
  eventScope: string | null;
  /** Monotonic generation for scoped loads — stale responses are dropped. */
  _eventGen: number;
  /** Monotonic generation for the global queue refresh — a slow poll response
   *  must not overwrite a newer refresh / socket update (ISSUE-207 review). */
  _queueGen: number;

  _pollTimer: ReturnType<typeof setInterval> | null;
  _globalSocketUnsub: (() => void) | null;
  _eventIds: string[];

  refreshEventIds: () => Promise<string[]>;
  loadPendingApprovals: (eventIds?: string[]) => Promise<QueueRefreshResult>;
  /** Load one event's waiting_approval actions into the scoped state (deep link).
   *  Never touches the global queue / _eventIds. Resolves ok/failed. */
  loadPendingApprovalsForEvent: (eventId: string) => Promise<QueueRefreshResult>;
  /** Clear the deep-link scope (call on page unmount); global queue untouched. */
  clearEventScope: () => void;
  /** Resolve to the backend ActionOperationResponse so callers can surface resume_status/degraded (ISSUE-207). */
  approve: (actionId: string, body: ApprovalDecisionBody) => Promise<ActionOperationResponse>;
  reject: (actionId: string, body: ApprovalDecisionBody) => Promise<ActionOperationResponse>;
  initGlobalListener: () => void;
  startPolling: (eventIds?: string[]) => void;
  stopPolling: () => void;
  clearUnread: () => void;
  _applySocketEvent: (event: SocketEvent) => void;
}

const APPROVAL_STATUSES = new Set(["waiting_approval", "approved", "rejected"]);

async function fetchWaitingApprovals(
  eventIds: string[],
): Promise<{
  perEvent: Array<{ eventId: string; items: Action[]; ok: boolean }>;
  fulfilled: number;
  total: number;
}> {
  if (eventIds.length === 0) return { perEvent: [], fulfilled: 0, total: 0 };
  const results = await Promise.allSettled(
    eventIds.map((id) =>
      listActions(id, { page_size: 200, status: "waiting_approval" }).then(
        (r) => ({ eventId: id, items: r.data.items }),
      ),
    ),
  );
  const perEvent: Array<{ eventId: string; items: Action[]; ok: boolean }> = [];
  let fulfilled = 0;
  for (let i = 0; i < results.length; i += 1) {
    const r = results[i];
    if (r.status === "fulfilled") {
      fulfilled += 1;
      perEvent.push({ eventId: eventIds[i], items: r.value.items, ok: true });
    } else {
      perEvent.push({ eventId: eventIds[i], items: [], ok: false });
    }
  }
  return { perEvent, fulfilled, total: results.length };
}

export const useApprovalStore = create<ApprovalState>((set, get) => ({
  pendingApprovals: [],
  loading: false,
  error: null,
  unreadCount: 0,
  approvalDeadlines: {},
  eventPendingApprovals: [],
  eventLoading: false,
  eventError: null,
  eventScope: null,
  _eventGen: 0,
  _queueGen: 0,
  _pollTimer: null,
  _globalSocketUnsub: null,
  _eventIds: [],

  async refreshEventIds() {
    try {
      const res = await listEvents({ page_size: 200 });
      const ids = res.data.items.map((e) => e.event_id);
      set({ _eventIds: ids });
      return ids;
    } catch {
      return get()._eventIds;
    }
  },

  async loadPendingApprovals(eventIds) {
    const ids = eventIds ?? get()._eventIds;
    if (ids.length === 0) {
      // Invalidate any in-flight non-empty refresh before clearing the queue so
      // a slow response cannot resurrect approvals for events that no longer
      // exist, and clear _eventIds so the polling timer stops requesting old
      // events (ISSUE-207 review).
      set((s) => ({
        _queueGen: s._queueGen + 1,
        _eventIds: [],
        pendingApprovals: [],
        loading: false,
        error: null,
      }));
      return "ok";
    }
    const gen = get()._queueGen + 1;
    set({ _queueGen: gen, loading: true, error: null, _eventIds: ids });
    const { perEvent, fulfilled, total } = await fetchWaitingApprovals(ids);
    // A newer refresh (poll, socket or 409 handling) superseded this one — drop
    // the stale result instead of overwriting newer state (ISSUE-207 review).
    if (get()._queueGen !== gen) return "failed";
    if (fulfilled === 0) {
      // Total failure: keep the previous queue instead of wiping it, and
      // report failure so callers (e.g. 409 handling) don't claim success.
      set({ loading: false, error: `审批队列加载失败（${total} 个事件全部请求失败）` });
      return "failed";
    }
    if (fulfilled < total) {
      // Partial: successful events replace their data; failed events keep the
      // old pending actions so no approval is silently lost (ISSUE-207 review).
      const failedIds = new Set(perEvent.filter((e) => !e.ok).map((e) => e.eventId));
      const fresh = perEvent.filter((e) => e.ok).flatMap((e) => e.items);
      const kept = get().pendingApprovals.filter((a) => failedIds.has(a.event_id));
      const merged = [...kept, ...fresh].sort((a, b) =>
        (a.updated_at ?? "").localeCompare(b.updated_at ?? ""),
      );
      set({
        pendingApprovals: merged,
        loading: false,
        error: `部分事件加载失败（${total - fulfilled}/${total}）`,
      });
      return "partial";
    }
    const all = perEvent
      .flatMap((e) => e.items)
      .sort((a, b) => (a.updated_at ?? "").localeCompare(b.updated_at ?? ""));
    set({ pendingApprovals: all, loading: false, error: null });
    return "ok";
  },

  async loadPendingApprovalsForEvent(eventId) {
    const gen = get()._eventGen + 1;
    // Keep the previous scoped items on a re-load of the same event so a failed
    // refresh does not wipe approvals the operator could still act on. A scope
    // switch (different event) still clears the stale data (ISSUE-207 review).
    const sameScope = get().eventScope === eventId;
    set({
      _eventGen: gen,
      eventScope: eventId,
      eventPendingApprovals: sameScope ? get().eventPendingApprovals : [],
      eventLoading: true,
      eventError: null,
    });
    try {
      const { data } = await listActions(eventId, {
        page_size: 200,
        status: "waiting_approval",
      });
      if (get()._eventGen !== gen) return "failed"; // superseded by a newer scope
      set({ eventPendingApprovals: data.items, eventLoading: false });
      return "ok";
    } catch (err: unknown) {
      if (get()._eventGen !== gen) return "failed";
      // Keep previous scoped items on failure; surface the scoped error only.
      set({ eventLoading: false, eventError: String(err) });
      return "failed";
    }
  },

  clearEventScope() {
    set((s) => ({
      eventScope: null,
      eventPendingApprovals: [],
      eventLoading: false,
      eventError: null,
      _eventGen: s._eventGen + 1,
    }));
  },

  async approve(actionId, body) {
    const { data } = await approveAction(actionId, body);
    // Bump the queue generation like the socket path does, so an in-flight poll
    // snapshot (taken before this decision) cannot resurrect the action; the
    // decision is authoritative so the loading spinner ends too.
    set((s) => ({
      _queueGen: s._queueGen + 1,
      loading: false,
      pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== actionId),
      eventPendingApprovals: s.eventPendingApprovals.filter((a) => a.action_id !== actionId),
    }));
    return data;
  },

  async reject(actionId, body) {
    const { data } = await rejectAction(actionId, body);
    set((s) => ({
      _queueGen: s._queueGen + 1,
      loading: false,
      pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== actionId),
      eventPendingApprovals: s.eventPendingApprovals.filter((a) => a.action_id !== actionId),
    }));
    return data;
  },

  initGlobalListener() {
    socketClient.connect();

    if (!get()._globalSocketUnsub) {
      const unsub = socketClient.onEvent((event) => {
        if (event.type === "approval_required" || event.type === "approval_updated") {
          get()._applySocketEvent(event);
        }
      });
      set({ _globalSocketUnsub: unsub });
    }

    void get()
      .refreshEventIds()
      .then((ids) => {
        void get().loadPendingApprovals(ids);
        get().startPolling(ids);
      });
  },

  startPolling(eventIds) {
    const { _pollTimer } = get();
    if (_pollTimer) clearInterval(_pollTimer);
    if (eventIds && eventIds.length > 0) {
      set({ _eventIds: eventIds });
    }

    const timer = setInterval(() => {
      const ids = get()._eventIds;
      if (ids.length > 0) void get().loadPendingApprovals(ids);
    }, 10_000);
    set({ _pollTimer: timer });
  },

  stopPolling() {
    const { _pollTimer } = get();
    if (_pollTimer) clearInterval(_pollTimer);
    set({ _pollTimer: null });
  },

  _applySocketEvent(event) {
    if (event.type !== "approval_required" && event.type !== "approval_updated") return;
    const action_id = event.payload?.action_id ?? "";
    if (!action_id) return;

    if (event.type === "approval_updated") {
      // Bump the queue generation so an in-flight poll response cannot restore
      // an action the socket just removed, and end the loading spinner since the
      // socket state is authoritative (ISSUE-207 review).
      set((s) => ({
        _queueGen: s._queueGen + 1,
        loading: false,
        pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== action_id),
        eventPendingApprovals: s.eventPendingApprovals.filter((a) => a.action_id !== action_id),
        approvalDeadlines: Object.fromEntries(
          Object.entries(s.approvalDeadlines).filter(([id]) => id !== action_id),
        ),
      }));
      return;
    }

    const deadline = event.payload.deadline;
    if (deadline) {
      set((s) => ({
        approvalDeadlines: { ...s.approvalDeadlines, [action_id]: deadline },
      }));
    }

    set((s) => ({ unreadCount: s.unreadCount + 1 }));
    const summary = event.payload.summary;
    notification.info({
      message: "新的审批请求",
      description: summary ? `${action_id}: ${summary}` : `动作 ${action_id} 需要审批`,
      placement: "topRight",
    });

    void get()
      .refreshEventIds()
      .then((ids) => get().loadPendingApprovals(ids));
  },

  clearUnread() {
    set({ unreadCount: 0 });
  },
}));

/** Revision progress for one event plan revision. */
export interface RevisionProgress {
  eventId: string;
  planRevision: number;
  decided: number;
  total: number;
}

export function revisionProgressKey(eventId: string, planRevision: number): string {
  return `${eventId}:${planRevision}`;
}

/** Compute decided/total approval counts per event revision. */
export async function loadRevisionProgress(
  pending: Action[],
): Promise<Map<string, RevisionProgress>> {
  const result = new Map<string, RevisionProgress>();
  const eventIds = [...new Set(pending.map((a) => a.event_id))];

  await Promise.all(
    eventIds.map(async (eventId) => {
      const { data } = await listActions(eventId, { page_size: 200 });
      const revisions = new Set(
        pending
          .filter((a) => a.event_id === eventId)
          .map((a) => a.plan_revision ?? 0),
      );
      for (const planRevision of revisions) {
        const inRev = data.items.filter((a) => (a.plan_revision ?? 0) === planRevision);
        const approvalSet = inRev.filter((a) => APPROVAL_STATUSES.has(a.status));
        const total = approvalSet.length;
        const decided = approvalSet.filter((a) => a.status !== "waiting_approval").length;
        result.set(revisionProgressKey(eventId, planRevision), {
          eventId,
          planRevision,
          decided,
          total,
        });
      }
    }),
  );

  return result;
}

/** Dev/mock approver label shown in the approval modal (read-only). */
export function currentApproverDisplay(): string {
  // Mock stage: prefer explicit env; future: read from auth context / token subject.
  return (
    import.meta.env.VITE_AUTH_SUBJECT ??
    import.meta.env.VITE_APPROVER_DISPLAY ??
    "审批员 (dev)"
  );
}

export function newDecisionId(): string {
  return crypto.randomUUID();
}

/** Fallback timeout when socket deadline is unavailable (30 minutes). */
export const APPROVAL_TIMEOUT_FALLBACK_MS = 30 * 60 * 1000;

export function isActionTimedOut(
  action: Action,
  deadline: string | undefined,
): boolean {
  if (deadline) {
    return Date.now() > new Date(deadline).getTime();
  }
  if (!action.updated_at) return false;
  return Date.now() - new Date(action.updated_at).getTime() > APPROVAL_TIMEOUT_FALLBACK_MS;
}

export function formatDispositionPreview(
  ref: Record<string, unknown> | null | undefined,
): string {
  if (!ref || Object.keys(ref).length === 0) return "—";
  const parts: string[] = [];
  for (const key of [
    "source_record_id",
    "object_type",
    "object_id",
    "field",
    "value",
  ]) {
    const val = ref[key];
    if (val !== undefined && val !== null && val !== "") {
      parts.push(`${key}=${String(val)}`);
    }
  }
  if (parts.length > 0) return parts.join("; ");
  const raw = JSON.stringify(ref);
  return raw.length > 160 ? `${raw.slice(0, 160)}…` : raw;
}
