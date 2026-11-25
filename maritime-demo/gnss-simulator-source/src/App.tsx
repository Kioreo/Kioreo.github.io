import { useState } from 'react';
import AttackChain from './AttackChain';
import Header from './Header';
import Instruments from './Instruments';
import Map from './Map';
import useLabState from './useLabState';

export default function App() {
  const connection = useLabState();
  const [following, setFollowing] = useState(true);
  const [followToken, setFollowToken] = useState(0);
  const refocus = () => {
    setFollowing(true);
    setFollowToken(value => value + 1);
  };

  return (
    <main className="app-shell">
      <Header {...connection} following={following} onFollow={refocus} />
      <div className="simulator-grid">
        <Map state={connection.state} following={following} followToken={followToken} />
        <Instruments state={connection.state} />
      </div>
      <AttackChain state={connection.state} />
      {!connection.state && <div className="loading-screen"><b>RMA GUI INITIALIZING</b><span>{connection.error || '시뮬레이터 상태 연결 중'}</span></div>}
    </main>
  );
}
