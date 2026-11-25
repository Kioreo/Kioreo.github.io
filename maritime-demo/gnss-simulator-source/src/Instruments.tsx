// Composes the actual RMA gui_instruments Rudder, LED, seven-segment and panel components.
import { useMemo } from 'react';
import RudderContext from './rma/instrument/contexts/RudderContext';
import Rudder from './rma/instrument/rudder/Rudder';
import BorderedBox from './rma/instrument/UI/BorderedBox';
import MetalLabel from './rma/instrument/UI/MetalLabel';
import SevenSegmentDisplay from './rma/instrument/UI/SevenSegmentDisplay/SevenSegmentDisplay';
import LEDPanel from './rma/instrument/UI/LEDPanel/LEDPanel';
import { ILEDPanelElement, State } from './rma/instrument/UI/LEDPanel/Element';
import DuoToneBar from './rma/instrument/UI/DuoToneBar/DuoToneBar';
import { LabState, asNumber, clamp, toLatLng } from './types';

const read = (value: unknown, fallback = 0) => asNumber(value) ?? fallback;
const display = (value: unknown, digits: number, width = 0) => {
  const parsed = asNumber(value);
  if (parsed === null) return ' '.repeat(Math.max(width, 1));
  const content = parsed.toFixed(digits);
  return width ? content.padStart(width, '0') : content;
};

const sourceLabel = (source: string) => source.includes('gps-aux') ? 'GPS 2 / AUX' : source.includes('gps-primary') ? 'GPS 1 / PRIMARY' : source || 'UNKNOWN';
const xteLabel = (value: number | null) => value === null ? '—' : `${value > 0 ? 'P' : value < 0 ? 'S' : ''} ${Math.abs(value).toFixed(1)} m`;

export default function Instruments({ state }: { state: LabState | null }) {
  const heading = asNumber(state?.physics?.heading ?? state?.autopilot?.heading_deg);
  const desired = asNumber(state?.autopilot?.desired_heading_deg);
  const cog = asNumber(state?.navigation?.course_over_ground_deg);
  const sog = asNumber(state?.navigation?.speed_over_ground_knots ?? state?.physics?.speed_knots);
  const xte = asNumber(state?.autopilot?.xte_m);
  const actualXte = asNumber(state?.metrics?.actual_xte_m);
  const bias = asNumber(state?.aux?.bias_m ?? state?.metrics?.gps_bias_m);
  const rudder = asNumber(state?.plc?.actual_rudder_deg ?? state?.physics?.rudder) ?? 0;
  const rudderCommand = asNumber(state?.plc?.command_rudder_deg ?? state?.autopilot?.rudder_command_deg) ?? 0;
  const source = String(state?.selected_source || state?.navigation?.source || 'UNKNOWN');
  const auxSelected = source.includes('gps-aux');
  const carryActive = Boolean(state?.aux?.attack_active);
  const modbus = state?.autopilot?.modbus_connected !== false && state?.physics?.plc_ok !== false;
  const headingDelta = heading === null || desired === null ? 0 : Math.abs((((heading - desired) + 540) % 360) - 180);
  const abnormal = auxSelected || carryActive || Math.abs(actualXte ?? 0) >= 12;
  const position = toLatLng(state?.positions?.perceived || state?.perceived_position);
  const actualPosition = toLatLng(state?.positions?.actual || state?.actual_position);
  const reportedPosition = toLatLng(state?.positions?.reported || state?.reported_position);
  const coordinate = (value: [number, number] | null) => value ? `${value[0].toFixed(6)}° N  ${value[1].toFixed(6)}° E` : 'POSITION UNAVAILABLE';

  const leds = useMemo<ILEDPanelElement[]>(() => [
    { text: 'MASTER', color: '#00ec86', state: state ? State.On : State.Off },
    { text: 'TRACK', color: '#00ec86', state: state ? State.On : State.Off },
    { text: 'GPS 2', color: '#ff4d5f', state: auxSelected ? State.Flashing : State.Off },
    { text: 'MODBUS', color: modbus ? '#00ec86' : '#ff4d5f', state: modbus ? State.On : State.Flashing },
  ], [auxSelected, modbus, state]);

  return (
    <aside className={`instrument-console ${abnormal ? 'console-alarm' : ''}`} aria-label="RMA 선교 계기 통합 패널">
      <div className="console-title">
        <span>BRIDGE INSTRUMENTS</span>
        <b className={abnormal ? 'danger-text pulse' : 'normal-text'}>{abnormal ? 'NAV DATA WARNING' : 'SYSTEM NORMAL'}</b>
      </div>
      <BorderedBox style={{ display: 'block', borderColor: abnormal ? '#a92636' : '#586873', padding: 5 }}>
        <MetalLabel style={{ margin: '0 0 6px', fontSize: 12 }}>AUTOPILOT / TRACK CONTROL</MetalLabel>
        <LEDPanel elements={leds} />
        <div className="digital-row">
          <div className={headingDelta >= 2 ? 'digital alarm-card' : 'digital'}>
            <span>GYRO HDG</span>
            <SevenSegmentDisplay content={display(heading, 1, 5)} size={5} backgroundColor="#030708" onColor="#ffb83e" offColor="#281e0b" sizeMultiplier={1.35} />
            <small>°T</small>
          </div>
          <div className="digital">
            <span>A/P SET</span>
            <SevenSegmentDisplay content={display(desired, 1, 5)} size={5} backgroundColor="#030708" onColor="#57d7ff" offColor="#09212b" sizeMultiplier={1.35} />
            <small>°T</small>
          </div>
        </div>
        <div className="digital-row compact">
          <div className="digital"><span>COG</span><b>{cog === null ? '—' : `${cog.toFixed(1)}°T`}</b></div>
          <div className="digital"><span>SOG</span><b>{sog === null ? '—' : `${sog.toFixed(1)} kn`}</b></div>
        </div>
      </BorderedBox>

      <div className="rudder-and-track">
        <div className={Math.abs(rudder) >= .5 && auxSelected ? 'rudder-wrap alarm-card' : 'rudder-wrap'}>
          <RudderContext.Provider value={{ position: clamp(rudder / 35, -1, 1), setPosition: () => undefined }}>
            <div className="readonly-rudder"><Rudder maxRudderAngle={35} divisions={3} /></div>
          </RudderContext.Provider>
          <div className="rudder-readout">ACT {rudder.toFixed(1)}° · CMD {rudderCommand.toFixed(1)}°</div>
        </div>
        <div className="track-values">
          <div className={Math.abs(xte ?? 0) >= 12 ? 'value-tile alarm-card' : 'value-tile'}><span>A/P XTE</span><b>{xteLabel(xte)}</b><small>선택 GNSS 기준</small></div>
          <div className={Math.abs(actualXte ?? 0) >= 12 ? 'value-tile alarm-card' : 'value-tile'}><span>ACTUAL XTE</span><b>{xteLabel(actualXte)}</b><small>물리 모델 기준</small></div>
          <div className={carryActive || (bias ?? 0) >= 1 ? 'value-tile alarm-card' : 'value-tile'}><span>GPS OFFSET</span><b>{bias === null ? '—' : `${bias.toFixed(1)} m`}</b><DuoToneBar percentage={clamp(read(bias) / 250 * 100, -100, 100)} labels={['0', '250 m']} /></div>
        </div>
      </div>

      <section className={auxSelected ? 'source-selector compromised' : 'source-selector'}>
        <span>SELECTED POSITION SOURCE</span>
        <b>{sourceLabel(source)}</b>
        <small>{position ? `${Math.abs(position[0]).toFixed(6)}° N · ${Math.abs(position[1]).toFixed(6)}° E` : 'POSITION UNAVAILABLE'}</small>
      </section>
      <section className="position-compare" aria-label="선체 위치와 GNSS 보고 위치 비교">
        <h2>POSITION INTEGRITY <small>WGS84 · LIVE LAB</small></h2>
        <div><span>실제 선체</span><b>{coordinate(actualPosition)}</b></div>
        <div><span>GNSS 보고</span><b>{coordinate(reportedPosition)}</b></div>
        <p className={auxSelected ? 'affected' : ''}>두 위치 편차 <strong>{(asNumber(state?.metrics?.gps_bias_m) ?? 0).toFixed(1)} m</strong></p>
      </section>
    </aside>
  );
}
