// Directly based on RMA-Naval-Cyber-Range gui_attack/src/Map.tsx and Ship.tsx (AGPL-3.0).
// The RMA WebSocket NMEA source is replaced with this lab's read-only /api/state feed.
import L, { LatLngExpression } from 'leaflet';
import { useEffect, useMemo, useRef, useState } from 'react';
import { CircleMarker, MapContainer, Marker, Polyline, TileLayer, Tooltip, useMap } from 'react-leaflet';
import { LabState, Position, asNumber, toLatLng } from './types';

function ownShipIcon(heading: number): L.DivIcon {
  const safeHeading = Number.isFinite(heading) ? heading : 0;
  return L.divIcon({
    className: 'own-ship-div-icon',
    iconSize: [48, 48],
    iconAnchor: [24, 24],
    tooltipAnchor: [25, -15],
    html: `
      <div class="own-ship-symbol" style="--ship-heading:${safeHeading.toFixed(2)}deg">
        <svg viewBox="0 0 48 48" role="presentation" aria-hidden="true">
          <line class="ship-heading-stem" x1="24" y1="0" x2="24" y2="9" />
          <path class="ship-hull" d="M24 5 L33 15 L31 37 Q24 43 17 37 L15 15 Z" />
          <path class="ship-deck" d="M24 10 L29 17 L28 31 Q24 34 20 31 L19 17 Z" />
          <line class="ship-centerline" x1="24" y1="8" x2="24" y2="38" />
          <circle class="ship-port-light" cx="18" cy="17" r="2" />
          <circle class="ship-starboard-light" cx="30" cy="17" r="2" />
          <circle class="ship-pivot" cx="24" cy="25" r="2.4" />
        </svg>
      </div>`,
  });
}

function FollowOwnShip({ position, enabled, token, overviewStart }: { position: [number, number]; enabled: boolean; token: number; overviewStart: [number, number] | null }) {
  const map = useMap();
  const latitude = position[0];
  const longitude = position[1];
  const startLat = overviewStart?.[0];
  const startLon = overviewStart?.[1];
  useEffect(() => {
    if (!enabled) return;
    if (startLat !== undefined && startLon !== undefined) {
      map.fitBounds([[startLat, startLon], [latitude, longitude]], { padding: [70, 70], maxZoom: 12, animate: false });
    } else {
      map.setView([latitude, longitude], 14, { animate: false });
    }
  }, [enabled, latitude, longitude, startLat, startLon, map, token]);
  return null;
}

function validTrack(track?: Position[]): LatLngExpression[] {
  if (!Array.isArray(track)) return [];
  return track.map(toLatLng).filter((point): point is [number, number] => point !== null);
}

function destination(origin: [number, number], bearingDegrees: number, distanceMetres: number): [number, number] {
  const radians = bearingDegrees * Math.PI / 180;
  const north = Math.cos(radians) * distanceMetres;
  const east = Math.sin(radians) * distanceMetres;
  return [origin[0] + north / 111_320, origin[1] + east / (111_320 * Math.cos(origin[0] * Math.PI / 180))];
}

function bearingBetween(start: [number, number], end: [number, number]): number {
  const meanLatitude = (start[0] + end[0]) * Math.PI / 360;
  const north = (end[0] - start[0]) * 111_320;
  const east = (end[1] - start[1]) * 111_320 * Math.cos(meanLatitude);
  return (Math.atan2(east, north) * 180 / Math.PI + 360) % 360;
}

interface MapProps {
  state: LabState | null;
  following: boolean;
  followToken: number;
}

export default function Map({ state, following, followToken }: MapProps) {
  const [mapTilesFailed, setMapTilesFailed] = useState(false);
  const actual = toLatLng(state?.positions?.actual || state?.actual_position) || [35.1, 129.13] as [number, number];
  const selected = toLatLng(state?.positions?.perceived || state?.perceived_position || state?.reported_position);
  const heading = asNumber(state?.physics?.heading ?? state?.autopilot?.heading_deg) ?? 0;
  const desired = asNumber(state?.autopilot?.desired_heading_deg) ?? heading;
  const source = String(state?.selected_source || state?.navigation?.source || 'unknown');
  const auxSelected = source.includes('gps-aux');
  const carryActive = Boolean(state?.aux?.attack_active);
  const auxCandidate = toLatLng(state?.aux?.reported as Position | undefined);
  const actualTrack = useMemo(() => validTrack(state?.actual_track), [state?.actual_track]);
  const reportedTrack = useMemo(() => validTrack(state?.reported_track), [state?.reported_track]);
  const shipIcon = useMemo(() => ownShipIcon(heading), [heading]);
  const fallbackPlan = useRef<{ origin: [number, number]; bearing: number } | null>(null);
  if (!fallbackPlan.current) fallbackPlan.current = { origin: actual, bearing: desired };
  const routeStart = toLatLng(state?.route?.start);
  const routeWaypoint = toLatLng(state?.route?.waypoint);
  const routeDistanceKm = routeStart ? Math.hypot(
    (actual[0] - routeStart[0]) * 111.32,
    (actual[1] - routeStart[1]) * 111.32 * Math.cos(actual[0] * Math.PI / 180),
  ) : 0;
  const showCoastContext = Boolean(routeStart && routeWaypoint && !auxSelected && !carryActive && routeDistanceKm > 5);
  const plannedOrigin = routeStart || fallbackPlan.current.origin;
  const plannedBearing = routeStart && routeWaypoint
    ? bearingBetween(routeStart, routeWaypoint)
    : fallbackPlan.current.bearing;
  // The planned course is fixed in geographic space.  Extending the route
  // keeps it visible during a long accelerated presentation without anchoring
  // either endpoint to the continuously moving own-ship position.
  const plannedCourse = [
    destination(plannedOrigin, plannedBearing + 180, 20_000),
    destination(plannedOrigin, plannedBearing, 350_000),
  ] as LatLngExpression[];
  const headingVector = [actual, destination(actual, heading, 650)] as LatLngExpression[];
  const separation = selected ? actual[0] !== selected[0] || actual[1] !== selected[1] : false;

  return (
    <section className="map-shell" aria-label="RMA 기반 전자해도 통합 화면">
      <MapContainer center={actual} zoom={14} zoomControl={true} attributionControl={true} preferCanvas={true}>
        <TileLayer
          attribution='&copy; OpenStreetMap contributors'
          url="https://tile.openstreetmap.org/{z}/{x}/{y}.png"
          eventHandlers={{ tileerror: () => setMapTilesFailed(true), tileload: () => setMapTilesFailed(false) }}
        />
        <TileLayer
          attribution='&copy; OpenSeaMap contributors'
          url="https://tiles.openseamap.org/seamark/{z}/{x}/{y}.png"
        />
        <FollowOwnShip position={actual} enabled={following} token={followToken} overviewStart={showCoastContext ? routeStart : null} />
        <Polyline positions={plannedCourse} pathOptions={{ color: '#36b9ff', weight: 2, dashArray: '10 8', opacity: 0.92 }} />
        {actualTrack.length > 1 && <Polyline positions={actualTrack} pathOptions={{ color: '#20f3a2', weight: 4, opacity: 0.9 }} />}
        {auxSelected && reportedTrack.length > 1 && <Polyline positions={reportedTrack} pathOptions={{ color: '#ffb541', weight: 3, dashArray: '5 7', opacity: 0.95 }} />}
        <Polyline positions={headingVector} pathOptions={{ color: '#20f3a2', weight: 2, opacity: 0.85 }} />
        {auxSelected && selected && separation && <Polyline positions={[actual, selected]} pathOptions={{ color: '#ff3f56', weight: 2, dashArray: '3 5' }} />}
        {carryActive && !auxSelected && auxCandidate && <Polyline positions={[actual, auxCandidate]} pathOptions={{ color: '#ffb541', weight: 2, dashArray: '4 6', opacity: .8 }} />}
        <Marker position={actual} icon={shipIcon} zIndexOffset={1000}>
          <Tooltip permanent direction="right" className="ship-tooltip">OWN SHIP · ACTUAL<br />HDG {heading.toFixed(1)}°T</Tooltip>
        </Marker>
        {auxSelected && selected && (
          <CircleMarker center={selected} radius={9} pathOptions={{ color: '#ffb541', weight: 3, fillColor: '#07131a', fillOpacity: 0.75 }}>
            <Tooltip permanent direction="left" className="reported-tooltip">EQUIPMENT POSITION<br />{source}</Tooltip>
          </CircleMarker>
        )}
        {carryActive && !auxSelected && auxCandidate && (
          <CircleMarker center={auxCandidate} radius={8} pathOptions={{ color: '#ffb541', weight: 2, fillColor: '#07131a', fillOpacity: 0.65 }}>
            <Tooltip permanent direction="left" className="reported-tooltip">GPS 2 INPUT · NOT SELECTED</Tooltip>
          </CircleMarker>
        )}
      </MapContainer>
      <div className="map-heading">
        <small>RMA REACT-LEAFLET NAVIGATION VIEW</small>
        <b>OWN SHIP / SELECTED GNSS POSITION</b>
      </div>
      <div className="map-legend">
        <span><i className="planned" />계획 침로</span>
        <span><i className="actual" />실제 항적</span>
        <span><i className="selected" />장비 사용 위치</span>
      </div>
      {showCoastContext && <aside className="map-journey-note">항로 전체 보기 · 출발점에서 {routeDistanceKm.toFixed(0)} km 항해</aside>}
      {mapTilesFailed && <div className="map-tile-warning">지도 타일 연결 대기 중 · 선박 위치와 계기는 계속 표시됩니다.</div>}
      <div className={`map-phase ${auxSelected ? 'affected' : carryActive ? 'injection' : ''}`}>
        <small>{auxSelected ? 'POSITION INTEGRITY LOST' : carryActive ? 'UNSELECTED GPS 2 INPUT ACTIVE' : 'POSITION INTEGRITY NORMAL'}</small>
        <b>{auxSelected ? 'GPS 2 데이터로 조타 계산 중' : carryActive ? 'GPS 2는 조작 중 · 장비는 GPS 1 사용' : '실제 위치와 장비 위치 일치'}</b>
      </div>
    </section>
  );
}
