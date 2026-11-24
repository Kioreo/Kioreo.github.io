import { AttackStage, LabState, asNumber } from './types';

const definitions = [
  { number: 1, tag: 'LAB STAGE 01', title: 'FUXA 프로젝트 정보 노출', wait: 'exploit-1-probe → exploit-1 실행 대기' },
  { number: 2, tag: 'LAB STAGE 02', title: 'FUXA RCE · 내부망 피벗', wait: 'exploit-2-execute → exploit-2 실행 대기' },
  { number: 3, tag: 'LAB STAGE 03', title: 'AUX GNSS 선택 · carry-off', wait: 'exploit-3-inject → exploit-3 실행 대기' },
];

function findStage(stages: AttackStage[], number: number): AttackStage | undefined {
  const needle = ['47718', '43947', '33951'][number - 1];
  return stages.find((item, index) => Number(item.stage ?? item.number) === number || String(item.id ?? item.name ?? '').includes(needle) || index === number - 1);
}

function evidenceText(number: number, stage?: AttackStage): string {
  if (!stage) return definitions[number - 1].wait;
  const evidence = stage.evidence || {};
  if (number === 1) {
    const script = evidence.script || {};
    return `인증 없이 점검 스크립트 읽음 → ${script.name || script.id || '정보 획득'}`;
  }
  if (number === 2) {
    const target = evidence.target || evidence.internal_target || evidence.pivot || evidence.command;
    return `서버 명령 실행 성공 → ${typeof target === 'string' ? target : '내부 Signal K 접근'}`;
  }
  const selected = evidence.selected_source || evidence.source || 'gps-aux.GP';
  return `항법 위치 소스 GPS 1 → ${typeof selected === 'string' ? selected : 'GPS 2'} 변경`;
}

export default function AttackChain({ state }: { state: LabState | null }) {
  const chain = state?.attack_chain;
  const runStatus = String(chain?.run_status || 'idle').toLowerCase();
  const prepared = !['idle', 'reset'].includes(runStatus);
  const current = prepared ? Math.max(0, Math.min(3, Number(chain?.current_stage ?? 0))) : -1;
  const stages = Array.isArray(chain?.stages) ? chain!.stages! : [];
  const source = String(state?.selected_source || 'gps-primary.GP');
  const bias = asNumber(state?.aux?.bias_m ?? state?.metrics?.gps_bias_m) ?? 0;
  const apXte = asNumber(state?.autopilot?.xte_m) ?? 0;
  const rudder = asNumber(state?.plc?.actual_rudder_deg ?? state?.physics?.rudder) ?? 0;
  const actualXte = asNumber(state?.metrics?.actual_xte_m) ?? 0;
  const carryActive = Boolean(state?.aux?.attack_active);

  return (
    <section className="attack-deck" aria-label="단계별 익스플로잇과 항해 영향">
      <div className="attack-visuals">
        <div className="exploit-strip">
          {definitions.map((definition) => {
            const record = findStage(stages, definition.number);
            const passed = current >= definition.number || String(record?.status).toLowerCase() === 'passed';
            const injecting = definition.number === 3 && current === 2 && carryActive;
            const ready = prepared && current === definition.number - 1;
            return (
              <article key={definition.number} className={`exploit-step ${passed ? 'passed' : injecting ? 'injecting' : ready ? 'ready' : 'locked'}`}>
                <span className="step-number">{definition.number}</span>
                <div><small>{definition.tag}</small><b>{definition.title}</b><p>{passed ? evidenceText(definition.number, record) : injecting ? 'GPS 2 데이터 주입 중 · GPS 1 선택 유지' : !prepared && definition.number === 1 ? 'prepare 실행 필요' : definition.wait}</p></div>
                <em>{passed ? '성공' : injecting ? '주입됨' : ready ? '실행 가능' : '잠김'}</em>
              </article>
            );
          })}
        </div>
        <div className="effect-strip">
          <div><span>① GNSS INPUT</span><b className={bias >= 1 ? 'warn' : ''}>AUX {bias.toFixed(1)} m</b></div>
          <i>›</i>
          <div><span>② SOURCE</span><b className={source.includes('gps-aux') ? 'warn' : ''}>{source.includes('gps-aux') ? 'GPS 2' : 'GPS 1'}</b></div>
          <i>›</i>
          <div><span>③ AUTOPILOT</span><b className={Math.abs(apXte) >= 1 ? 'warn' : ''}>XTE {Math.abs(apXte).toFixed(1)} m</b></div>
          <i>›</i>
          <div><span>④ MODBUS PLC</span><b className={Math.abs(rudder) >= .5 ? 'warn' : ''}>RUDDER {rudder.toFixed(1)}°</b></div>
          <i>›</i>
          <div><span>⑤ OWN SHIP</span><b className={Math.abs(actualXte) >= 12 ? 'danger-text pulse' : ''}>XTE {Math.abs(actualXte).toFixed(1)} m</b></div>
        </div>
      </div>
    </section>
  );
}
