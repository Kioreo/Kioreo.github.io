import { useCallback, useEffect, useRef, useState } from 'react';
import { LabConnection, LabState } from './types';

function stateUrl(): string {
  const requested = new URLSearchParams(location.search).get('feed');
  if (requested) {
    try {
      const url = new URL(requested);
      if (url.protocol === 'https:' && url.pathname === '/api/state' && !url.username && !url.password) return url.href;
    } catch { /* Keep local feed. */ }
  }
  return new URL('../api/state', location.href).href;
}

export default function useLabState(): LabConnection {
  const [state, setState] = useState<LabState | null>(null);
  const [connected, setConnected] = useState(false);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastSuccess = useRef(0);
  const polling = useRef(false);

  const poll = useCallback(async () => {
    if (polling.current) return;
    polling.current = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(stateUrl(), { cache: 'no-store', signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const next = await response.json() as LabState;
      if (!next.positions?.actual) throw new Error('선체 위치 없음');
      setState(next);
      setConnected(true);
      setStale(false);
      setError(null);
      lastSuccess.current = Date.now();
    } catch (reason) {
      setConnected(false);
      setStale(lastSuccess.current > 0);
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      window.clearTimeout(timeout);
      polling.current = false;
    }
  }, []);

  useEffect(() => {
    void poll();
    const timer = window.setInterval(() => void poll(), 1500);
    return () => window.clearInterval(timer);
  }, [poll]);

  return { state, connected, stale, error };
}
