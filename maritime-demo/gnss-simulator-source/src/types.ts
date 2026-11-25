export interface Position {
  latitude?: number;
  longitude?: number;
  lat?: number;
  lon?: number;
  timestamp?: string | null;
  source?: string;
}

export interface AttackStage {
  stage?: number;
  number?: number;
  id?: string;
  name?: string;
  status?: string;
  completed_at?: string;
  evidence?: Record<string, any>;
  [key: string]: any;
}

export interface LabState {
  ok?: boolean;
  partial?: boolean;
  phase?: string;
  selected_source?: string;
  positions?: { actual?: Position; perceived?: Position; reported?: Position };
  actual_position?: Position;
  perceived_position?: Position;
  reported_position?: Position;
  navigation?: Record<string, any>;
  physics?: Record<string, any>;
  autopilot?: Record<string, any>;
  plc?: Record<string, any>;
  aux?: Record<string, any>;
  route?: Record<string, Position>;
  actual_track?: Position[];
  reported_track?: Position[];
  selected_track?: Position[];
  metrics?: Record<string, any>;
  turn_effect?: Record<string, any>;
  attack_chain?: {
    current_stage?: number;
    run_status?: string;
    run_id?: string;
    stages?: AttackStage[];
  };
  errors?: Record<string, any>;
  [key: string]: any;
}

export interface LabConnection {
  state: LabState | null;
  connected: boolean;
  stale: boolean;
  error: string | null;
}

export function asNumber(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function toLatLng(value?: Position | null): [number, number] | null {
  if (!value) return null;
  const latitude = asNumber(value.latitude ?? value.lat);
  const longitude = asNumber(value.longitude ?? value.lon);
  return latitude === null || longitude === null ? null : [latitude, longitude];
}

export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
