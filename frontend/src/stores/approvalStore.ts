/** Approval store — pending approvals with socket-driven updates (ISSUE-073). */

import { create } from "zustand";
import { notification } from "antd";
import type { Action } from "../types/action";
import { listActions, approveAction, rejectAction } from "../services/eventApi";
import { socketClient } from "../services/socketClient";
import type { SocketEvent } from "../types/socket";

interface ApprovalState {
  /** All pending approval actions across events. */
  pendingApprovals: Action[];
  loading: boolean;
  error: string | null;
  /** Unread approval-required socket events (bell badge). */
  unreadCount: number;

  /** Polling timer handle. */
  _pollTimer: ReturnType<typeof setInterval> | null;
  _socketUnsub: (() => void) | null;
  _eventIds: string[];

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

  /** Reset unread badge count. */
  clearUnread: () => void;

  /** Apply a socket-driven update: add or remove an approval. */
  _applySocketEvent: (event: SocketEvent) => void;
}

export const useApprovalStore = create<ApprovalState>((set, get) => ({
  pendingApprovals: [],
  loading: false,
  error: null,
  unreadCount: 0,
  _pollTimer: null,
  _socketUnsub: null,
  _eventIds: [],

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
    await approveAction(actionId, { comment });
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
    set({ _eventIds: eventIds });

    // Ensure socket is connected
    socketClient.connect();

    // Socket listener
    if (!_socketUnsub) {
      const unsub = socketClient.onEvent((event) => {
        if (event.type === "approval_required" || event.type === "approval_updated") {
          get()._applySocketEvent(event);
        }
      });
      set({ _socketUnsub: unsub });
    }

    // 10-second polling fallback — reads eventIds from store to avoid stale closure
    const timer = setInterval(() => {
      const ids = get()._eventIds;
      if (ids.length > 0) get().loadPendingApprovals(ids);
    }, 10_000);
    set({ _pollTimer: timer });
  },

  stopPolling() {
    const { _pollTimer, _socketUnsub } = get();
    if (_pollTimer) clearInterval(_pollTimer);
    if (_socketUnsub) _socketUnsub();
    set({ _pollTimer: null, _socketUnsub: null });
  },

  _applySocketEvent(event: SocketEvent) {
    const action_id = event.payload?.action_id as string ?? "";
    if (event.type === "approval_updated") {
      set((s) => ({
        pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== action_id),
      }));
    }
    if (event.type === "approval_required") {
      set((s) => ({ unreadCount: s.unreadCount + 1 }));
      notification.info({
        message: "新的审批请求",
        description: `动作 ${action_id} 需要审批`,
        placement: "topRight",
      });
      // Trigger immediate refresh to show the new card
      const ids = get()._eventIds;
      if (ids.length > 0) get().loadPendingApprovals(ids);
    }
  },

  clearUnread() {
    set({ unreadCount: 0 });
  },
}));
