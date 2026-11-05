"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { AssessmentDetail, AssessmentEvent } from "./types";
import { getAssessment } from "./api";

export function useAssessmentStream(assessmentId: string | null) {
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [events, setEvents] = useState<AssessmentEvent[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<
    "CONNECTING" | "LIVE" | "PAUSED" | "COMPLETED" | "DISCONNECTED"
  >("CONNECTING");
  const eventSourceRef = useRef<EventSource | null>(null);
  const lastEventIdRef = useRef<number>(0);

  const refresh = useCallback(async () => {
    if (!assessmentId) return;
    try {
      const data = await getAssessment(assessmentId);
      setAssessment(data);
      if (data.is_terminal) {
        setConnectionStatus("COMPLETED");
      } else if (data.status === "PAUSED") {
        setConnectionStatus("PAUSED");
      } else if (data.status === "RUNNING") {
        setConnectionStatus("LIVE");
      }
    } catch (err) {
      console.error("Failed to poll assessment state", err);
    }
  }, [assessmentId]);

  useEffect(() => {
    if (!assessmentId) {
      setAssessment(null);
      setEvents([]);
      return;
    }

    refresh();

    const connectSSE = () => {
      const url = `/api/v1/assessments/${assessmentId}/events`;
      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onopen = () => {
        setConnectionStatus("LIVE");
      };

      const handleEvent = (e: MessageEvent, eventType: string) => {
        try {
          const payload = JSON.parse(e.data);
          const evt: AssessmentEvent = {
            id: e.lastEventId ? parseInt(e.lastEventId, 10) : Date.now(),
            eventType,
            node: payload.node,
            data: payload,
            timestamp: new Date().toISOString(),
          };
          if (e.lastEventId) {
            lastEventIdRef.current = parseInt(e.lastEventId, 10);
          }
          setEvents((prev) => [...prev, evt]);
          refresh();
        } catch {
          // Heartbeat or non-json message
        }
      };

      const eventNames = [
        "assessment_created",
        "assessment_started",
        "scope_validated",
        "recon_completed",
        "action_proposed",
        "action_approved",
        "action_blocked",
        "tool_completed",
        "finding_verified",
        "assessment_paused",
        "assessment_resumed",
        "report_generated",
        "assessment_completed",
        "assessment_failed",
        "cancel_requested",
        "node_transition",
      ];

      eventNames.forEach((name) => {
        es.addEventListener(name, (e) => handleEvent(e as MessageEvent, name));
      });

      es.onerror = () => {
        if (es.readyState === EventSource.CLOSED) {
          setConnectionStatus("DISCONNECTED");
        }
      };
    };

    connectSSE();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, [assessmentId, refresh]);

  return { assessment, events, connectionStatus, refresh };
}

