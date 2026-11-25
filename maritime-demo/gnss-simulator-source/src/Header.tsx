import { useEffect, useState } from 'react';
import { LabConnection } from './types';

interface HeaderProps extends LabConnection { onFollow: () => void; following: boolean; }

export default function Header({ state, connected, stale, error, onFollow, following }: HeaderProps) {
  const [clock, setClock] = useState('');
  useEffect(() => {
    const update = () => setClock(new Date().toLocaleTimeString('ko-KR', { hour12: false }));
    update(); const timer = window.setInterval(update, 1000); return () => window.clearInterval(timer);
  }, []);
  const source = String(state?.selected_source || 'gps-primary.GP');
  const aux = source.includes('gps-aux');
  const stage = Math.max(0, Math.min(3, Number(state?.attack_chain?.current_stage ?? 0)));
  const bridge = new URL('../bridge-simulator/index.html', location.href);
  const landing = new URL('../index.html', location.href);
  const feed = new URLSearchParams(location.search).get('feed');
  if (feed) { bridge.searchParams.set('feed', feed); landing.searchParams.set('feed', feed); }
  return <header className="range-navbar">
    <div className="brand-block"><span className="brand-mark">HS</span><span><b>HSPACE EXPLORER</b><small>MARITIME GNSS CYBER RANGE · LIVE SIMULATOR</small></span></div>
    <nav className="range-nav" aria-label="해도 상태">
      <button className={`nav-chip ${following ? 'active' : ''}`} onClick={onFollow}>자선 중심</button>
      <span className="nav-chip">ATTACK STAGE <b>{stage}/3</b></span>
      <span className={`nav-chip ${aux ? 'danger' : 'good'}`}>POS <b>{aux ? 'GPS 2 / AUX' : 'GPS 1 / PRIMARY'}</b></span>
      <span className={`nav-chip ${state?.phase === 'deviating' ? 'danger' : 'good'}`}>{state?.phase === 'deviating' ? 'ROUTE DEVIATION' : 'NAV INPUT NORMAL'}</span>
    </nav>
    <div className="header-actions">
      <a className="nav-back" href={bridge.href}>3D 선교</a><a className="nav-back" href={landing.href}>처음 화면</a>
      <span className={`connection ${connected ? 'online' : 'offline'}`} title={error || ''}><i />{connected ? 'SIM LIVE' : stale ? 'SIM STALE' : 'SIM OFFLINE'}</span>
      <time>{clock}</time>
    </div>
  </header>;
}
