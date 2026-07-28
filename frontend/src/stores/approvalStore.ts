/** Approval store — pending approvals with socket-driven updates (ISSUE-073). */

import { create } from "zustand";
import type { Action } from "../types/action";
import { listActions, approveAction, rejectAction } from "../services/eventApi";
import { socketClient } from "../services/socketClient";

interface ApprovalState {
  /** All pending approval actions across events. */
  pendingApprovals: Action[];
  loading: boolean;
  error: string | null;

  /** Polling timer handle. */
  _pollTimer: ReturnType<typeof setInterval> | null;
  _socketUnsub: (() => void) | null;

  /** Fetch all WAITING_APPROVAL actions from the server (initial load). */
  loadPendingApprovals: (eventIds: string[]) => Promise<void>;

  /** Approve an action, then refresh the list. */
  approve: (actionId: string, comment?: string) => Promise<void>;

  /** Reject an action (requires comment), then refresh. */
  reject: (actionId: string, comment: string) => Promise<void>;

  /** Start 10-second polling as fallback when socket is unavailable. */
  startPolling: (eventIds: string[]) => void;

  /** Stop polling and disconnect socket listener. */
  stopPolling: () => void;

  /** Apply a socket-driven update: add or remove an approval. */
  _applySocketEvent: (event: ApprovalSocketEvent) => void;
}

interface ApprovalSocketEvent {
  type: "approval_required" | "approval_updated";
  action_id: string;
  event_id?: string;
  status?: string;
}

export const useApprovalStore = create<ApprovalState>((set, get) => ({
  pendingApprovals: [],
  loading: false,
  error: null,
  _pollTimer: null,
  _socketUnsub: null,

  async loadPendingApprovals(eventIds: string[]) {
    set({ loading: true, error: null });
    try {
      const results = await Promise.allSettled(
        eventIds.map((id) =>
          listActions(id, { page_size: 200 }).then(
            (r) => r.data.items.filter((a) => a.status === "waiting_approval"),
          ),
        ),
      );
      const all: Action[] = [];
      for (const r of results) {
        if (r.status === "fulfilled") all.push(...r.value);
      }
      all.sort((a, b) => (a.updated_at ?? "").localeCompare(b.updated_at ?? ""));
      set({ pendingApprovals: all, loading: false });
    } catch (err: unknown) {
      set({ error: String(err), loading: false });
    }
  },

  async approve(actionId: string, comment?: string) {
    await approveAction(actionId);
    set((s) => ({
      pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== actionId),
    }));
  },

  async reject(actionId: string, comment: string) {
    await rejectAction(actionId, { comment });
    set((s) => ({
      pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== actionId),
    }));
  },

  startPolling(eventIds: string[]) {
    const { _pollTimer, _socketUnsub } = get();
    if (_pollTimer) clearInterval(_pollTimer);

    // Socket listener
    if (!_socketUnsub) {
      const unsub = socketClient.onEvent((envelope: Record<string, unknown>) => {
        const type = envelope?.type as string | undefined;
        if (type === "approval_required" || type === "approval_updated") {
          get()._applySocketEvent(envelope as unknown as ApprovalSocketEvent);
        }
      });
      set({ _socketUnsub: unsub });
    }

    // 10-second polling fallback
    const timer = setInterval(() => {
      get().loadPendingApprovals(eventIds);
    }, 10_000);
    set({ _pollTimer: timer });
  },

  stopPolling() {
    const { _pollTimer, _socketUnsub } = get();
    if (_pollTimer) clearInterval(_pollTimer);
    if (_socketUnsub) _socketUnsub();
    set({ _pollTimer: null, _socketUnsub: null });
  },

  _applySocketEvent(event: ApprovalSocketEvent) {
    const { type, action_id } = event;
    if (type === "approval_updated") {
      // Remove the action from pending list (already decided)
      set((s) => ({
        pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== action_id),
      }));
    }
    // For 'approval_required', a refresh is more reliable than constructing the Action
    // from socket payload fields; the 10 s poll will pick it up.
    if (type === "approval_required") {
      // Immediately trigger a refresh
      const store = get();
      // We don't have eventIds here; the caller should restart polling
      // but the existing poll timer will pick it up on next cycle.
    }
  },
}));
