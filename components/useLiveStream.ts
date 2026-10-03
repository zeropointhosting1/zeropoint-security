"use client";

import { useEffect, useRef, useState } from "react";
import type { LiveAlert } from "@/lib/types";
import { alertColor, alertLabel } from "@/lib/format";
import type { Beacon } from "./GlobeView";

const POLL_MS = 60_000;
const BEACON_MS = 7_000;
const MAX_BEACONS = 14;
const STREAM_LENGTH = 80;
/** On first load, stream events from the last 2 hours (at least 30) in publish order. */
const BACKLOG_MS = 2 * 60 * 60 * 1000;
const BACKLOG_MIN = 30;

/**
 * Streams real feed events into the UI one at a time, oldest first, so new
 * reports "arrive" the way the feeds published them. Every alert keeps its
 * source timestamp; the pacing only spreads out events that the feeds publish
 * in batches (abuse.ch exports refresh about every 5 minutes).
 */
export function useLiveStream() {
  const [stream, setStream] = useState<LiveAlert[]>([]);
  const [beacons, setBeacons] = useState<Beacon[]>([]);
  const [latest, setLatest] = useState<Beacon | null>(null);
  const [pending, setPending] = useState(0);
  const [connected, setConnected] = useState(false);
  const queue = useRef<LiveAlert[]>([]);
  const seen = useRef(new Set<string>());

  // Poll the lightweight alerts endpoint and queue anything we haven't seen.
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch("/api/alerts");
        if (!res.ok) throw new Error(String(res.status));
        const { alerts } = (await res.json()) as { alerts: LiveAlert[] };
        if (cancelled) return;
        const first = seen.current.size === 0;
        const cutoff = Date.now() - BACKLOG_MS;
        const backlog = alerts.filter((a, i) => i < BACKLOG_MIN || Date.parse(a.time) >= cutoff);
        const fresh = (first ? backlog : alerts.filter((a) => !seen.current.has(a.id)))
          .slice()
          .reverse(); // oldest first
        for (const a of alerts) seen.current.add(a.id);
        queue.current = [...queue.current, ...fresh].sort((a, b) => a.time.localeCompare(b.time));
        setPending(queue.current.length);
        setConnected(true);
      } catch {
        if (!cancelled) setConnected(false);
      }
    };
    poll();
    const id = setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  // Release queued events one at a time; faster while catching up on a backlog.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const removals = new Set<ReturnType<typeof setTimeout>>();
    const step = () => {
      const backlog = queue.current.length;
      if (backlog && !document.hidden) {
        const a = queue.current.shift()!;
        setPending(queue.current.length);
        setStream((prev) => [a, ...prev].slice(0, STREAM_LENGTH));
        if (typeof a.lat === "number" && typeof a.lon === "number") {
          const b: Beacon = {
            id: `${a.id}-${Date.now()}`,
            lat: a.lat,
            lon: a.lon,
            color: alertColor(a.kind),
            kind: a.kind,
            label: `${alertLabel(a.kind)} · ${a.countryCode ?? ""}`,
          };
          setBeacons((prev) => [...prev, b].slice(-MAX_BEACONS));
          setLatest(b);
          const r = setTimeout(() => {
            removals.delete(r);
            setBeacons((prev) => prev.filter((x) => x.id !== b.id));
          }, BEACON_MS);
          removals.add(r);
        }
      }
      timer = setTimeout(step, backlog > 40 ? 900 : backlog > 10 ? 1800 : backlog ? 3200 : 2000);
    };
    timer = setTimeout(step, 1200);
    return () => {
      clearTimeout(timer);
      removals.forEach(clearTimeout);
    };
  }, []);

  return { stream, beacons, latest, pending, connected };
}
