"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { AssessmentDetail, AssessmentEvent } from "./types";
import { getAssessment } from "./api";

export type ConnectionStatus =
  | "CONNECTING"
  | "LIVE"
  | "PAUSED"
  | "COMPLETED"
  | "DISCONNECTED";

const TERMINAL_EVENTS = new Set([
  "assessment_completed",
  "assessment_failed",
  "stream_closed",
]);

const EVENT_NAMES = [
  "assessment_created",
  "assessment_started",
  "scope_validated",
  "recon_started",
  "recon_completed",
  "planning_started",
  "action_proposed",
  "action_approved",
  "action_blocked",
  "tool_started",
  "tool_completed",
  "verification_started",
  "recovery_started",
  "finding_verified",
  "completion_check",
  "assessment_paused",
  "assessment_resumed",
  "report_generated",
  "langfuse_trace_linked",
  "assessment_completed",
  "assessment_failed",
  "cancel_requested",
  "node_transition",
  "stream_closed",
];

export function useAssessmentStream(assessmentId: string | null) {
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [events, setEvents] = useState<AssessmentEvent[]>([]);
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("CONNECTING");

  const eventSourceRef = useRef<EventSource | null>(null);
  const lastEventIdRef = useRef<number>(0);
  const terminalRef = useRef<boolean>(false);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    if (!assessmentId) return;
    try {
      const data = await getAssessment(assessmentId);
      setAssessment(data);
      if (data.is_terminal) {
        terminalRef.current = true;
        setConnectionStatus("COMPLETED");
      } else if (data.status === "PAUSED") {
        setConnectionStatus("PAUSED");
      } else if (data.status === "RUNNING" || data.status === "QUEUED") {
        setConnectionStatus((prev) => (prev === "PAUSED" ? prev : "LIVE"));
      }
    } catch (err) {
      console.error("Failed to poll assessment state", err);
    }
  }, [assessmentId]);

  // Coalesce the many per-event refreshes that happen when the SSE endpoint
  // replays a backlog of events in one burst.
  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) return;
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 200);
  }, [refresh]);

  useEffect(() => {
    if (!assessmentId) {
      setAssessment(null);
      setEvents([]);
      setConnectionStatus("CONNECTING");
      return;
    }

    // Reset per-assessment state on navigation.
    setEvents([]);
    lastEventIdRef.current = 0;
    terminalRef.current = false;
    setConnectionStatus("CONNECTING");
    void refresh();

    const closeConnection = () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };

    const handleEvent = (e: MessageEvent, eventType: string) => {
      let payload: Record<string, unknown> = {};
      try {
        payload = e.data ? JSON.parse(e.data) : {};
      } catch {
        // Heartbeat or non-JSON message.
        return;
      }

      const parsedId = e.lastEventId ? parseInt(e.lastEventId, 10) : NaN;
      const payloadId =
        typeof payload.event_id === "number" ? payload.event_id : NaN;
      const id = Number.isFinite(parsedId)
        ? parsedId
        : Number.isFinite(payloadId)
          ? payloadId
          : Date.now();

      if (Number.isFinite(parsedId)) {
        lastEventIdRef.current = parsedId;
      }

      const evt: AssessmentEvent = {
        id,
        eventType,
        node: (payload.node as string) || undefined,
        data: payload,
        timestamp:
          typeof payload.timestamp === "string"
            ? payload.timestamp
            : new Date().toISOString(),
      };

      setEvents((prev) => {
        if (prev.some((existing) => existing.id === id)) return prev;
        return [...prev, evt].sort((a, b) => a.id - b.id);
      });

      if (TERMINAL_EVENTS.has(eventType)) {
        terminalRef.current = true;
        setConnectionStatus("COMPLETED");
        closeConnection();
        void refresh();
        return;
      }

      if (eventType === "assessment_paused") {
        setConnectionStatus("PAUSED");
      }

      scheduleRefresh();
    };

    const connectSSE = () => {
      const cursor = lastEventIdRef.current;
      const url = `/api/v1/assessments/${assessmentId}/events${
        cursor > 0 ? `?last_event_id=${cursor}` : ""
      }`;
      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onopen = () => {
        if (terminalRef.current) return;
        setConnectionStatus((prev) => (prev === "PAUSED" ? prev : "LIVE"));
      };

      EVENT_NAMES.forEach((name) => {
        es.addEventListener(name, (e) => handleEvent(e as MessageEvent, name));
      });

      es.onerror = () => {
        // A terminal assessment closes the stream by design. Otherwise let the
        // browser reconnect automatically; transient proxy errors must not
        // permanently kill live telemetry.
        if (terminalRef.current) {
          closeConnection();
          setConnectionStatus("COMPLETED");
          return;
        }
        if (es.readyState === EventSource.CLOSED) {
          setConnectionStatus((prev) =>
            prev === "PAUSED" ? prev : "DISCONNECTED",
          );
          void refresh();
        } else {
          setConnectionStatus((prev) =>
            prev === "PAUSED" ? prev : "CONNECTING",
          );
        }
      };
    };

    connectSSE();

    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
      closeConnection();
    };
  }, [assessmentId, refresh, scheduleRefresh]);

  return { assessment, events, connectionStatus, refresh };
}
