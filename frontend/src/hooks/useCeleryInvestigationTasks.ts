import { useCallback, useEffect, useRef, useState } from "react";
import type { CeleryInvestigationTrack } from "../types/event";
import { getTask } from "../services/eventApi";
import { isTerminalTaskState, normalizeTaskState } from "../utils/investigationTaskTracking";

const POLL_INTERVAL_MS = 3_000;

export interface RegisterCeleryTrackInput {
  event_id: string;
  task_id: string;
  intent_id?: string | null;
  state?: string;
}

export interface UseCeleryInvestigationTasksResult {
  tracksByEventId: ReadonlyMap<string, CeleryInvestigationTrack>;
  registerTrack: (input: RegisterCeleryTrackInput) => void;
  clearTrack: (eventId: string) => void;
}

/**
 * Minimal celery task polling for POST /investigate responses.
 * Polls GET /tasks/{task_id} until a terminal public state is observed.
 */
export function useCeleryInvestigationTasks(
  enabled: boolean,
): UseCeleryInvestigationTasksResult {
  const [tracksByEventId, setTracksByEventId] = useState<
    Map<string, CeleryInvestigationTrack>
  >(() => new Map());
  const tracksRef = useRef(tracksByEventId);
  tracksRef.current = tracksByEventId;

  const registerTrack = useCallback((input: RegisterCeleryTrackInput) => {
    setTracksByEventId((prev) => {
      const next = new Map(prev);
      next.set(input.event_id, {
        event_id: input.event_id,
        task_id: input.task_id,
        intent_id: input.intent_id ?? null,
        state: normalizeTaskState(input.state ?? "PENDING"),
      });
      return next;
    });
  }, []);

  const clearTrack = useCallback((eventId: string) => {
    setTracksByEventId((prev) => {
      if (!prev.has(eventId)) return prev;
      const next = new Map(prev);
      next.delete(eventId);
      return next;
    });
  }, []);

  const pollOnce = useCallback(async () => {
    const current = tracksRef.current;
    if (current.size === 0) return;

    const entries = [...current.entries()];
    const results = await Promise.all(
      entries.map(async ([eventId, track]) => {
        if (isTerminalTaskState(track.state)) {
          return [eventId, track] as const;
        }
        try {
          const res = await getTask(track.task_id);
          const nextState = normalizeTaskState(res.data.state);
          if (nextState === track.state) {
            return [eventId, track] as const;
          }
          return [
            eventId,
            {
              ...track,
              state: nextState,
            },
          ] as const;
        } catch {
          return [eventId, track] as const;
        }
      }),
    );

    setTracksByEventId((prev) => {
      let changed = false;
      const next = new Map(prev);
      for (const [eventId, track] of results) {
        const existing = prev.get(eventId);
        if (
          !existing ||
          existing.state !== track.state ||
          existing.task_id !== track.task_id ||
          existing.intent_id !== track.intent_id
        ) {
          next.set(eventId, track);
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, []);

  useEffect(() => {
    if (!enabled) return;
    void pollOnce();
    const timer = window.setInterval(() => {
      void pollOnce();
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [enabled, pollOnce]);

  return { tracksByEventId, registerTrack, clearTrack };
}
