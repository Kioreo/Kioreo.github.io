'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { AlertTriangle, Anchor, ArrowLeft, FileText, FileWarning, Folder, HardDrive, LockKeyhole, Power, Radio, RotateCcw, Server, ShieldCheck, Skull, Smartphone, Terminal, Wifi, X } from 'lucide-react';

function Button({ variant, size, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: string; size?: string }) {
  return <button {...props} />;
}
function Input(props: React.InputHTMLAttributes<HTMLInputElement>) { return <input {...props} />; }

type LabState = {
  phase?: string;
  selected_source?: string;
  navigation?: { speed_over_ground_knots?: number };
  turn_effect?: { heading_deg?: number; rudder_actual_deg?: number };
  metrics?: { actual_xte_m?: number };
};
const LOCK_KEY = 'hspace-maritime-ransomware-v1';
const PASSWORD_DIGEST = '0e1d1e8830347f97aa6323eb5a1f56b12a2df5af87dab59bf15be773bd3a6bfb';
async function validRecoveryKey(key: string): Promise<boolean> {
  const bytes = new TextEncoder().encode(key);
  if (!crypto.subtle) {
    let hash = 2166136261;
    for (const byte of bytes) hash = Math.imul(hash ^ byte, 16777619) >>> 0;
    return hash === 0x187b2713;
  }
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(x => x.toString(16).padStart(2, '0')).join('');
  return digest === PASSWORD_DIGEST;
}

function feedUrl(): string {
  const requested = new URLSearchParams(location.search).get('feed');
  if (requested) {
    try {
      const feed = new URL(requested);
      if (feed.protocol === 'https:' && feed.pathname === '/api/state' && !feed.username && !feed.password) return feed.href;
    } catch { /* Use local lab feed. */ }
  }
  return new URL('../api/state', location.href).href;
}

function BridgeScene({ phase }: { phase: number }) {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color('#7eb8d5');
    scene.fog = new THREE.FogExp2('#9ec5d6', 0.006);
    const camera = new THREE.PerspectiveCamera(56, 1, 0.1, 1000);
    camera.position.set(0, 5.2, 14);
    // Aim down from bridge height so the sea fills the lower half of each
    // forward window instead of being hidden behind the console geometry.
    camera.lookAt(0, -8.5, -48);
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, window.innerWidth < 950 ? 1.25 : 1.6));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    mount.appendChild(renderer.domElement);

    // Screen-space 3D bridge interior. The reference photo is not rendered;
    // every structural element below is procedural geometry.
    const cockpitScene = new THREE.Scene();
    const cockpitCamera = new THREE.OrthographicCamera(0, 100, 100, 0, -40, 40);
    cockpitCamera.position.z = 20;
    const cockpitAmbient = new THREE.HemisphereLight('#b7d5dc', '#071012', 1.35);
    const cockpitKey = new THREE.DirectionalLight('#d8edf0', 2.3);
    cockpitKey.position.set(-25, 70, 30);
    cockpitScene.add(cockpitAmbient, cockpitKey);

    const steel = new THREE.MeshStandardMaterial({ color: '#27363a', roughness: .52, metalness: .68 });
    const darkSteel = new THREE.MeshStandardMaterial({ color: '#10191c', roughness: .45, metalness: .78 });
    const consoleMaterial = new THREE.MeshStandardMaterial({ color: '#253538', roughness: .66, metalness: .42 });
    const rubber = new THREE.MeshStandardMaterial({ color: '#05090a', roughness: .88, metalness: .12 });
    const brass = new THREE.MeshStandardMaterial({ color: '#9d7337', roughness: .34, metalness: .82 });
    const deckMaterial = new THREE.MeshStandardMaterial({ color: '#111b1e', roughness: .92, metalness: .18 });
    const glassMaterial = new THREE.MeshStandardMaterial({ color: '#17353a', emissive: '#07181b', roughness: .18, metalness: .42 });
    const indicatorGreen = new THREE.MeshBasicMaterial({ color: '#56f0c5' });
    const indicatorAmber = new THREE.MeshBasicMaterial({ color: '#ffb92e' });

    const box = (x: number, y: number, width: number, height: number, depth: number, material: THREE.Material) => {
      const mesh = new THREE.Mesh(new THREE.BoxGeometry(width, height, depth), material);
      mesh.position.set(x, y, 0);
      mesh.castShadow = true;
      mesh.receiveShadow = true;
      cockpitScene.add(mesh);
      return mesh;
    };
    const polygon = (points: Array<[number, number]>, material: THREE.Material, z = 0) => {
      const shape = new THREE.Shape();
      points.forEach(([x, y], index) => index ? shape.lineTo(x, y) : shape.moveTo(x, y));
      shape.closePath();
      const mesh = new THREE.Mesh(new THREE.ShapeGeometry(shape), material);
      mesh.position.z = z;
      mesh.receiveShadow = true;
      cockpitScene.add(mesh);
      return mesh;
    };

    // Ceiling, side bulkheads, three forward window frames and lower sill.
    box(50, 96, 100, 12, 2.4, darkSteel);
    box(1.7, 71, 3.4, 44, 3.2, darkSteel);
    box(98.3, 71, 3.4, 44, 3.2, darkSteel);
    box(30.2, 73.5, 2.15, 37, 3.4, steel);
    box(68.3, 73.5, 2.15, 37, 3.4, steel);
    box(50, 56.2, 100, 3.4, 3.5, steel);
    box(50, 91.2, 100, 2.4, 2.8, steel);
    box(15.5, 74, .5, 34, .7, new THREE.MeshStandardMaterial({ color: '#78898c', roughness: .22, metalness: .9 }));
    box(84.5, 74, .5, 34, .7, new THREE.MeshStandardMaterial({ color: '#78898c', roughness: .22, metalness: .9 }));

    // Sloped integrated bridge console and instrument fascia.
    polygon([[0, 0], [0, 43], [7, 54.5], [93, 54.5], [100, 43], [100, 0]], consoleMaterial, 1);
    polygon([[4, 24], [8, 57], [92, 57], [96, 24]], darkSteel, 1.4);
    box(50, 32.4, 94, 2.1, 2.5, steel);
    box(50, 5.5, 100, 11, 4, darkSteel);

    // Lower command station: angled side consoles, footwell and anti-slip deck.
    polygon([[1.5, 2], [4.5, 27], [37.5, 27], [42, 2]], consoleMaterial, 2.1);
    polygon([[58, 2], [62.5, 27], [95.5, 27], [98.5, 2]], consoleMaterial, 2.1);
    polygon([[42, 1], [44.5, 22], [55.5, 22], [58, 1]], deckMaterial, 2.2);
    box(21.3, 22.5, 29.5, 1.25, 2.5, steel);
    box(78.7, 22.5, 29.5, 1.25, 2.5, steel);
    box(20.5, 14.4, 24, 8.8, 2, glassMaterial);
    box(79.5, 14.4, 24, 8.8, 2, glassMaterial);
    [46, 50, 54].forEach((x) => box(x, 5.7, 1.6, 8.5, 1.1, rubber));
    [44.5, 48.2, 51.8, 55.5].forEach((x) => box(x, 1.2, 2.1, .42, .7, steel));

    // Tactile switches and illuminated controls across both lower panels.
    const controlRows: Array<[number, number, number]> = [[10, 10.5, 7], [67.5, 10.5, 7]];
    controlRows.forEach(([startX, y, count], rowIndex) => {
      for (let control = 0; control < count; control += 1) {
        const lamp = box(startX + control * 3.45, y, 1.25, .72, .7, (control + rowIndex) % 4 === 0 ? indicatorAmber : indicatorGreen);
        lamp.position.z = 3.35;
        box(startX + control * 3.45, y - 2.1, 1.55, .62, .8, rubber).position.z = 3.2;
      }
    });

    // Three recessed analogue gauges on the port-side command panel.
    [14, 21, 28].forEach((x, index) => {
      const rim = new THREE.Mesh(new THREE.RingGeometry(2.05, 2.45, 32), steel);
      rim.position.set(x, 17.1, 3.35);
      cockpitScene.add(rim);
      const face = new THREE.Mesh(new THREE.CircleGeometry(1.98, 32), rubber);
      face.position.set(x, 17.1, 3.3);
      cockpitScene.add(face);
      const needle = box(x, 17.1, 1.75, .16, .18, index === 1 ? indicatorAmber : indicatorGreen);
      needle.position.z = 3.75;
      needle.rotation.z = -.7 + index * .55;
    });

    // Five monitor housings aligned with the live HTML navigation displays.
    const housings: Array<[number, number]> = [[10.25, 17.9], [29.2, 18], [48.3, 17.7], [68.15, 18.1], [88.6, 20.2]];
    housings.forEach(([x, width]) => {
      box(x, 47.2, width + 1.45, 25.1, 2.8, rubber);
      box(x, 34.1, width * .58, 1.2, 3.4, darkSteel);
      const led = box(x + width * .39, 34.15, .32, .32, .5, indicatorGreen);
      led.position.z = 2.1;
    });

    // Overhead bridge electronics and status lamps.
    [-17, 0, 17].forEach((offset, index) => {
      box(50 + offset, 94.1, 13.2, 3.8, 1.8, rubber);
      for (let lamp = 0; lamp < 4; lamp += 1) {
        const light = box(45.8 + offset + lamp * 2.8, 94.05, .35, .35, .5, (lamp + index) % 3 === 0 ? indicatorAmber : indicatorGreen);
        light.position.z = 1.35;
      }
    });

    // Central steering wheel, column and twin engine-order levers.
    const wheel = new THREE.Mesh(new THREE.TorusGeometry(6.1, .55, 12, 48), darkSteel);
    wheel.position.set(50, 15.6, 4);
    cockpitScene.add(wheel);
    for (let spoke = 0; spoke < 8; spoke += 1) {
      const arm = box(50, 15.6, 5.5, .42, .65, brass);
      arm.position.z = 3.8;
      arm.rotation.z = spoke * Math.PI / 4;
    }
    const hub = new THREE.Mesh(new THREE.CylinderGeometry(1.25, 1.25, 1.4, 24), brass);
    hub.rotation.x = Math.PI / 2;
    hub.position.set(50, 15.6, 4.3);
    cockpitScene.add(hub);
    box(50, 8.2, 5.2, 11, 3.8, darkSteel);
    [-1, 1].forEach((side) => {
      const lever = box(89 + side * 2.1, 17, .65, 8.5, .7, brass);
      lever.rotation.z = side * -.16;
      const handle = box(89 + side * 2.75, 21.1, 2.2, 1.25, 1.6, rubber);
      handle.rotation.z = side * -.16;
    });

    scene.add(new THREE.HemisphereLight('#e7f6ff', '#173142', 2.4));
    const sun = new THREE.DirectionalLight('#fff1d0', 3.1);
    sun.position.set(-40, 60, -30);
    scene.add(sun);

    const skyGeometry = new THREE.SphereGeometry(450, 32, 16);
    const skyMaterial = new THREE.ShaderMaterial({
      side: THREE.BackSide,
      uniforms: {
        topColor: { value: new THREE.Color('#3787b7') },
        bottomColor: { value: new THREE.Color('#d4ebee') },
      },
      vertexShader: 'varying vec3 vPos; void main(){ vPos=position; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }',
      fragmentShader: 'uniform vec3 topColor; uniform vec3 bottomColor; varying vec3 vPos; void main(){ float h=normalize(vPos).y; gl_FragColor=vec4(mix(bottomColor,topColor,smoothstep(-0.12,0.72,h)),1.0); }',
    });
    scene.add(new THREE.Mesh(skyGeometry, skyMaterial));

    const oceanGeometry = new THREE.PlaneGeometry(620, 620, 120, 120);
    oceanGeometry.rotateX(-Math.PI / 2);
    const oceanMaterial = new THREE.ShaderMaterial({
      uniforms: {
        time: { value: 0 },
        deep: { value: new THREE.Color('#073f5d') },
        crest: { value: new THREE.Color('#2f91ad') },
        sunDirection: { value: new THREE.Vector3(-0.4, 0.8, -0.2).normalize() },
      },
      vertexShader: `
        uniform float time;
        varying float vWave;
        varying vec2 vSeaPosition;
        varying vec3 vNormalW;
        void main() {
          vec3 p = position;
          float a = sin(p.x * .105 + time * 1.38) * .48;
          float b = sin(p.z * .085 - time * 1.02 + p.x * .035) * .34;
          float c = sin((p.x + p.z) * .16 + time * 1.92) * .14;
          p.y += a + b + c;
          vWave = p.y;
          vSeaPosition = p.xz;
          vNormalW = normalize(vec3(-.105*cos(p.x*.105+time*1.15), 1.0, .085*cos(p.z*.085-time*.82+p.x*.035)));
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
        }
      `,
      fragmentShader: `
        uniform float time;
        uniform vec3 deep;
        uniform vec3 crest;
        uniform vec3 sunDirection;
        varying float vWave;
        varying vec2 vSeaPosition;
        varying vec3 vNormalW;
        void main() {
          float light = pow(max(dot(normalize(vNormalW), sunDirection), 0.0), 2.0);
          float travellingRipple = sin(vSeaPosition.x * .31 + vSeaPosition.y * .18 + time * 2.2);
          float crossRipple = sin(vSeaPosition.x * -.16 + vSeaPosition.y * .27 - time * 1.55);
          float foam = smoothstep(.49, .76, vWave + travellingRipple * .07 + crossRipple * .04);
          float glint = pow(max(travellingRipple * crossRipple, 0.0), 7.0) * .13;
          vec3 color = mix(deep, crest, clamp(vWave + .5, 0.0, 1.0));
          color += light * vec3(.15,.23,.25) + foam * vec3(.32,.48,.51) + glint;
          gl_FragColor = vec4(color, 1.0);
        }
      `,
    });
    const ocean = new THREE.Mesh(oceanGeometry, oceanMaterial);
    ocean.position.y = -0.2;
    scene.add(ocean);

    const distantShip = new THREE.Group();
    const hull = new THREE.Mesh(new THREE.BoxGeometry(7.5, 1.4, 22), new THREE.MeshStandardMaterial({ color: '#26343b', roughness: 0.78 }));
    hull.position.y = 0.65;
    distantShip.add(hull);
    const superstructure = new THREE.Mesh(new THREE.BoxGeometry(5.8, 3.2, 5.5), new THREE.MeshStandardMaterial({ color: '#e1e5e4', roughness: 0.7 }));
    superstructure.position.set(0, 2.8, 5.5);
    distantShip.add(superstructure);
    distantShip.position.set(35, 0, -112);
    distantShip.scale.setScalar(0.7);
    scene.add(distantShip);

    const buoyMaterial = new THREE.MeshStandardMaterial({ color: '#e84b35', emissive: '#4b0700' });
    for (const [x, z] of [[-15, -46], [18, -72], [-32, -112]]) {
      const buoy = new THREE.Group();
      const body = new THREE.Mesh(new THREE.CylinderGeometry(.32, .5, 1.5, 12), buoyMaterial);
      const top = new THREE.Mesh(new THREE.SphereGeometry(.22, 12, 8), new THREE.MeshBasicMaterial({ color: '#ff684e' }));
      top.position.y = 1;
      buoy.add(body, top);
      buoy.position.set(x, .45, z);
      scene.add(buoy);
    }

    const resize = () => {
      const width = mount.clientWidth;
      const height = mount.clientHeight;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(mount);
    const startedAt = performance.now();
    let frame = 0;
    const animate = () => {
      frame = requestAnimationFrame(animate);
      const t = (performance.now() - startedAt) / 1000;
      oceanMaterial.uniforms.time.value = t;
      distantShip.position.x = 35 - (t % 120) * .16;
      camera.position.y = 5.2 + Math.sin(t * .55) * .09;
      camera.position.x = Math.sin(t * .19) * .025;
      camera.rotation.z = Math.sin(t * .42) * .0035;
      renderer.autoClear = true;
      renderer.render(scene, camera);
      renderer.autoClear = false;
      renderer.clearDepth();
      renderer.render(cockpitScene, cockpitCamera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      renderer.dispose();
      oceanGeometry.dispose();
      oceanMaterial.dispose();
      skyGeometry.dispose();
      skyMaterial.dispose();
      cockpitScene.traverse((object) => {
        if (!(object instanceof THREE.Mesh)) return;
        object.geometry.dispose();
      });
      [steel, darkSteel, consoleMaterial, rubber, brass, deckMaterial, glassMaterial, indicatorGreen, indicatorAmber].forEach((material) => material.dispose());
      mount.removeChild(renderer.domElement);
    };
  }, []);

  return <div ref={mountRef} className={`bridge-scene phase-${phase}`} aria-label="움직이는 바다가 보이는 선박 조타실" />;
}

function Radar({ failed }: { failed: boolean }) {
  return (
    <div className={`radar ${failed ? 'radar-failed' : ''}`} aria-label={failed ? '추적 신호가 손실된 X-band 레이더' : '정상 작동 중인 X-band 레이더'}>
      <span className="radar-sweep" /><span className="radar-ring radar-ring-a" /><span className="radar-ring radar-ring-b" />
      <span className="radar-line radar-line-x" /><span className="radar-line radar-line-y" />
      <i className="contact contact-a" /><i className="contact contact-b" /><i className="contact contact-c" />
      <span className="own-ship">▲</span>
    </div>
  );
}

function Ecdis({ failed, lab }: { failed: boolean; lab: LabState | null }) {
  return (
    <div className="ecdis-map">
      <svg viewBox="0 0 240 150" aria-label="부산항 접근 항로 전자해도">
        <title>부산항 접근 항로 전자해도</title>
        <path className="land" d="M0 0H92L78 28 105 52 89 74 105 101 86 150H0Z" />
        <path className="depth" d="M88 0C130 35 105 52 145 83s18 50 61 67" />
        <path className="route" d="M212 12 176 44 151 72 124 109 102 139" />
        <circle className="waypoint" cx="176" cy="44" r="4" /><circle className="waypoint" cx="151" cy="72" r="4" /><circle className="waypoint" cx="124" cy="109" r="4" />
        <path className="ship-mark" d="M142 83l-6 16 12-3z" />
      </svg>
      <span className="ecdis-label">{failed ? 'POSITION SOURCE INVALID' : lab?.selected_source?.includes('aux') ? `GPS 2 · XTE ${(lab.metrics?.actual_xte_m ?? 0).toFixed(1)} M` : 'BUSAN APPROACH · ROUTE 04'}</span>
    </div>
  );
}

function MonitorLock({ station }: { station: string }) {
  return (
    <div className="monitor-lock-screen">
      <Skull />
      <span>HAEYANG LOCKER</span>
      <strong>YOUR BRIDGE SYSTEM<br />HAS BEEN ENCRYPTED</strong>
      <p>Navigation workstation and voyage data are unavailable.</p>
      <div className="monitor-lock-metrics"><b>05<small>LOCKED</small></b><b>27<small>ALARMS</small></b><b>00:59:48<small>WINDOW</small></b></div>
      <em><LockKeyhole /> DO NOT RESTART BRIDGE EQUIPMENT</em>
      <small>{station} · OFFLINE TRAINING MODE</small>
    </div>
  );
}

function SystemDown() {
  return <div className="system-down-screen"><Power /><strong>SYSTEM DOWN</strong><span>RADAR WORKSTATION UNAVAILABLE</span><i /></div>;
}

const incidentStages = [
  'NORMAL VOYAGE',
  'GPS PRIMARY SOURCE INVALID',
  'ARPA TARGET PROCESSING LOST',
  'CONNING DATA BUS FROZEN',
  'PROPULSION MONITOR OFFLINE',
  'INTEGRATED BRIDGE COMPROMISED',
  'SYSTEMS ENCRYPTED',
];

let alarmContext: AudioContext | null = null;
function alarmTone(frequency = 680, duration = .13) {
  try {
    alarmContext ??= new AudioContext();
    const oscillator = alarmContext.createOscillator();
    const gain = alarmContext.createGain();
    oscillator.frequency.value = frequency;
    oscillator.type = 'square';
    gain.gain.setValueAtTime(.055, alarmContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(.001, alarmContext.currentTime + duration);
    oscillator.connect(gain).connect(alarmContext.destination);
    oscillator.start();
    oscillator.stop(alarmContext.currentTime + duration);
  } catch { /* Audio is optional in restricted browser environments. */ }
}

function Failure({ code, children }: { code: string; children: React.ReactNode }) {
  return <div className="failure-screen"><AlertTriangle /><strong>{children}</strong><span>FAULT CODE {code}</span></div>;
}

type BridgeDocument = Document & {
  modelContext?: {
    registerTool: (tool: {
      name: string;
      title: string;
      description: string;
      inputSchema: Record<string, unknown>;
      annotations: { readOnlyHint: boolean; untrustedContentHint: boolean };
      execute: (input: Record<string, unknown>) => unknown;
    }, options?: { signal?: AbortSignal }) => void | Promise<void>;
  };
};

export default function Home() {
  const [serverOpen, setServerOpen] = useState(false);
  const [phase, setPhase] = useState(() => sessionStorage.getItem(LOCK_KEY) === 'locked' ? 6 : 0);
  const [recoveryKey, setRecoveryKey] = useState('');
  const [recoveryError, setRecoveryError] = useState('');
  const [clock, setClock] = useState<Date | null>(null);
  const [telemetry, setTelemetry] = useState({ heading: 72.0, speed: 12.4, rpm: 72, temp: 81 });
  const [lab, setLab] = useState<LabState | null>(null);
  const timers = useRef<number[]>([]);
  const overviewUrl = new URL('../', location.href);
  const gnssUrl = new URL('../', location.href);
  const workstationUrl = new URL('../', location.href);
  gnssUrl.searchParams.set('view', 'gnss');
  workstationUrl.searchParams.set('view', 'workstation');
  const requestedFeed = new URLSearchParams(location.search).get('feed');
  if (requestedFeed) { overviewUrl.searchParams.set('feed', requestedFeed); gnssUrl.searchParams.set('feed', requestedFeed); workstationUrl.searchParams.set('feed', requestedFeed); }

  const stopSequence = useCallback(() => {
    timers.current.forEach(window.clearTimeout);
    timers.current = [];
  }, []);

  const beginIncident = useCallback(() => {
    if (phase > 0) return false;
    stopSequence();
    setServerOpen(false);
    sessionStorage.setItem(LOCK_KEY, 'locked');
    alarmTone(920, .18);
    [1, 2, 3, 4, 5, 6].forEach((stage, index) => {
      const timer = window.setTimeout(() => {
        setPhase(stage);
        alarmTone(stage >= 5 ? 360 : 760 - stage * 55, stage >= 5 ? .34 : .13);
      }, index === 0 ? 250 : 250 + index * 1450);
      timers.current.push(timer);
    });
    return true;
  }, [phase, stopSequence]);

  const restoreSystems = useCallback(async (key: string) => {
    if (!await validRecoveryKey(key)) return false;
    stopSequence();
    sessionStorage.removeItem(LOCK_KEY);
    setPhase(0);
    setServerOpen(false);
    setRecoveryKey('');
    setRecoveryError('');
    setTelemetry({ heading: 72.0, speed: 12.4, rpm: 72, temp: 81 });
    alarmTone(1080, .12);
    return true;
  }, [stopSequence]);

  useEffect(() => () => stopSequence(), [stopSequence]);

  useEffect(() => {
    const endpoint = feedUrl();
    let active = true;
    const poll = async () => {
      try {
        const response = await fetch(endpoint, { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const next = await response.json() as LabState;
        if (active) setLab(next);
      } catch { if (active) setLab(null); }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1500);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setClock(new Date());
      if (phase < 2) {
        const now = Date.now() / 1000;
        setTelemetry({
          heading: lab?.turn_effect?.heading_deg ?? 72 + Math.sin(now * .22) * .8,
          speed: lab?.navigation?.speed_over_ground_knots ?? 12.4 + Math.sin(now * .31) * .12,
          rpm: Math.round(72 + Math.sin(now * .44) * 2),
          temp: Math.round(81 + Math.sin(now * .09)),
        });
      }
    }, 400);
    return () => window.clearInterval(timer);
  }, [phase, lab]);

  useEffect(() => {
    const context = (document as BridgeDocument).modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    const register = async () => {
      await context.registerTool({
        name: 'start_maritime_cyber_incident',
        title: 'Start maritime cyber incident',
        description: 'Start the visible staged ransomware simulation on the local training bridge.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        execute: () => ({ started: beginIncident(), mode: 'authorized-training-simulation' }),
      }, { signal: lifecycle.signal });
      await context.registerTool({
        name: 'restore_maritime_bridge_systems',
        title: 'Restore maritime bridge systems',
        description: 'Restore the visible training bridge using its recovery key.',
        inputSchema: { type: 'object', properties: { recoveryKey: { type: 'string' } }, required: ['recoveryKey'], additionalProperties: false },
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        execute: async (input) => ({ restored: await restoreSystems(typeof input.recoveryKey === 'string' ? input.recoveryKey : '') }),
      }, { signal: lifecycle.signal });
    };
    void register().catch(() => undefined);
    return () => lifecycle.abort();
  }, [beginIncident, restoreSystems]);

  const recover = async (event: { preventDefault: () => void }) => {
    event.preventDefault();
    if (!await restoreSystems(recoveryKey)) {
      setRecoveryError('INVALID RECOVERY KEY · ACCESS DENIED');
      alarmTone(190, .28);
    }
  };

  const compromised = phase === 5;
  const gnssAffected = phase === 0 && lab?.phase !== undefined && lab.phase !== 'baseline';
  const voyageStatus = phase ? incidentStages[phase] : gnssAffected ? lab?.phase === 'deviating' ? 'GNSS ROUTE DEVIATION' : 'GNSS DATA ANOMALY' : 'NORMAL VOYAGE';
  const clockText = clock?.toLocaleTimeString('en-GB', { hour12: false }) ?? '--:--:--';
  return (
    <main className={`simulator-shell incident-phase-${phase}`}>
      <output className="portrait-notice"><Smartphone /><strong>가로 모드로 회전해주세요</strong><span>조타실 시뮬레이터는 가로 화면에 최적화되어 있습니다.</span></output>
      <BridgeScene phase={phase} />
      <div className="glass-reflection" aria-hidden="true" />
      <div className="emergency-wash" aria-hidden="true" />

      <header className="bridge-header">
        <div className="vessel-id"><Anchor size={17} /><span>SPACE XsHip</span><small>BRIDGE · CONNING POSITION 1</small></div>
        <div className={`system-health ${phase ? 'system-danger' : gnssAffected ? 'system-gnss' : ''}`}>{phase || gnssAffected ? <AlertTriangle size={15} /> : <ShieldCheck size={15} />}{voyageStatus}</div>
        <time>{clockText} KST</time>
      </header>

      <nav className="sim-nav" aria-label="시연 이동"><a href={overviewUrl.href}>시연 시작 화면</a><a href={workstationUrl.href}>선내 PC 문서함</a><a href={gnssUrl.href}>GNSS 전자해도</a></nav>
      <div className={`lab-readout ${lab?.selected_source?.includes('aux') ? 'affected' : ''}`} aria-live="polite">
        <span>{lab ? 'LIVE GNSS LAB' : 'GNSS LAB STANDBY'}</span>
        <b>{lab?.selected_source?.includes('aux') ? 'GPS 2 · AUX' : lab ? 'GPS 1 · PRIMARY' : 'FEED DISCONNECTED'}</b>
        <small>HDG {telemetry.heading.toFixed(1)}° · SOG {telemetry.speed.toFixed(1)} kn · RUDDER {(lab?.turn_effect?.rudder_actual_deg ?? 0).toFixed(1)}° · XTE {(lab?.metrics?.actual_xte_m ?? 0).toFixed(1)} m</small>
      </div>

      {phase > 0 && <aside className="incident-timeline"><span>INCIDENT PROGRESSION</span>{incidentStages.slice(1, 6).map((stage, index) => <div key={stage} className={phase > index ? 'reached' : ''}><i />{stage}</div>)}</aside>}

      <section className="monitor-bank" aria-label="선박 통합 조타 모니터">
        <article className={`monitor radar-monitor ${phase >= 2 ? 'failed' : ''}`}><div className="monitor-title"><span>X-BAND RADAR</span><b>{phase >= 2 ? 'ERR' : 'TX'}</b></div><Radar failed={phase >= 2} />{phase >= 2 && <Failure code="RDR-109">ARPA PROCESSOR LOST</Failure>}<div className="monitor-foot"><span>RNG 6 NM</span><span>{phase >= 2 ? 'TRACK LOST' : 'ARPA 3'}</span></div>{phase >= 6 && <SystemDown />}</article>
        <article className={`monitor ecdis-monitor ${phase >= 1 ? 'failed' : ''}`}><div className="monitor-title"><span>ECDIS 01</span><b>{phase >= 1 ? 'NO FIX' : lab?.selected_source?.includes('aux') ? 'GPS 2' : 'GPS 1'}</b></div><Ecdis failed={phase >= 1} lab={lab} />{phase >= 1 && <div className="ecdis-alert">⚠ NAVIGATION POSITION UNAVAILABLE</div>}<div className="monitor-foot"><span>HDG {telemetry.heading.toFixed(0)}°</span><span>{phase >= 1 ? 'POS LOST' : `SOG ${telemetry.speed.toFixed(1)} kn`}</span></div>{phase >= 6 && <MonitorLock station="ECDIS-01" />}</article>
        <article className={`monitor conning-monitor ${phase >= 3 ? 'failed' : ''}`}><div className="monitor-title"><span>CONNING</span><b>{phase >= 3 ? 'FROZEN' : 'AUTO'}</b></div>{phase >= 3 ? <Failure code="NAV-771">NMEA DATA BUS FROZEN</Failure> : <><div className="heading-value">{telemetry.heading.toFixed(0)}<span>°T</span></div><div className="heading-scale"><span>060</span><i /><i /><b>072</b><i /><i /><span>080</span></div><div className="conning-grid"><span>SOG<b>{telemetry.speed.toFixed(1)} kn</b></span><span>ROT<b>+0.2°/m</b></span><span>RUDDER<b>{(lab?.turn_effect?.rudder_actual_deg ?? 0).toFixed(1)}°</b></span></div></>}{phase >= 6 && <MonitorLock station="CONNING-01" />}</article>
        <article className={`monitor engine-monitor ${phase >= 4 ? 'failed' : ''}`}><div className="monitor-title"><span>PROPULSION</span><b>{phase >= 4 ? 'OFFLINE' : 'RUN'}</b></div>{phase >= 4 ? <Failure code="IAS-451">REMOTE I/O TIMEOUT</Failure> : <><div className="engine-dials"><div className="dial"><span className="needle needle-a" /><strong>{telemetry.rpm}</strong><small>RPM</small></div><div className="dial"><span className="needle needle-b" /><strong>{telemetry.temp}</strong><small>°C</small></div></div><div className="engine-bars"><span style={{ '--level': '76%' } as React.CSSProperties}>FUEL</span><span style={{ '--level': '63%' } as React.CSSProperties}>LOAD</span></div></>}{phase >= 6 && <MonitorLock station="PROP-01" />}</article>
        <article className={`monitor alarm-monitor ${phase >= 1 ? 'failed' : ''}`}><div className="monitor-title"><span>ALARM / IAS</span><b className={phase ? 'alarm-count' : 'healthy'}>{phase ? Math.min(27, phase * 5) : 0}</b></div>{phase ? <div className="alarm-stack"><strong>CRITICAL ALARMS</strong><span>GPS-1 SIGNAL FAILURE</span>{phase >= 2 && <span>RADAR PROC OFFLINE</span>}{phase >= 3 && <span>IBS NETWORK TIMEOUT</span>}{phase >= 4 && <span>PROP MONITOR LOST</span>}</div> : <div className="alarm-ok"><ShieldCheck /><strong>NO ACTIVE ALARMS</strong><span>Last check {clockText}</span></div>}<div className="network-row"><Radio size={13} /> NMEA 2000 BUS <b>{phase >= 3 ? 'OFFLINE' : 'ONLINE'}</b></div>{phase >= 6 && <MonitorLock station="ALARM-IAS" />}</article>
      </section>

      {compromised && <div className="compromise-banner"><Skull /><span>INTEGRATED BRIDGE NETWORK COMPROMISED</span><Skull /></div>}

      <aside className={`demo-controls ${phase ? 'controls-danger' : ''}`}>
        <div><span className="eyebrow">CYBER RANGE CONTROL</span><strong>{phase ? `STAGE ${phase}/6 · RUNNING` : voyageStatus}</strong></div>
        {(phase === 0 || phase >= 6) && <Button variant="outline" size="lg" onClick={() => setServerOpen(true)} className="server-button"><Server /> {phase >= 6 ? 'Recovery server' : 'Server'}</Button>}
        {phase > 0 && phase < 6 && <div className="live-indicator"><i /> LIVE</div>}
      </aside>

      <div className="training-badge">AUTHORIZED TRAINING SIMULATION · NO LIVE VESSEL CONNECTION</div>

      {serverOpen && <section className="ubuntu-screen" aria-label="훈련용 우분투 서버 화면">
        <header className="ubuntu-topbar"><button type="button">Activities</button><span>SPACE XsHip · Server Operations</span><time>{clockText}</time><Wifi /><Power /></header>
        <nav className="ubuntu-dock" aria-label="Ubuntu applications"><button type="button" aria-label="Files"><Folder /></button><button type="button" aria-label="Terminal"><Terminal /></button><button type="button" aria-label="Server status"><HardDrive /></button><i /><button type="button" aria-label="Back to bridge" onClick={() => setServerOpen(false)}><ArrowLeft /></button></nav>
        <div className="ubuntu-wallpaper"><span>24.04</span><b>SPACE XsHip</b><small>VESSEL OPERATIONS SERVER</small></div>
        {phase === 0 ? <article className="ubuntu-files">
          <header><div><button type="button" aria-label="Back"><ArrowLeft /></button><span>Downloads</span></div><button type="button" aria-label="Close" onClick={() => setServerOpen(false)}><X /></button></header>
          <div className="ubuntu-path"><span>woot</span><b>/</b><span>Downloads</span></div>
          <div className="ubuntu-file-grid">
            <div className="ubuntu-file"><Folder /><span>Vessel Reports</span></div>
            <div className="ubuntu-file"><FileText /><span>Crew_Rotation.pdf</span></div>
            <div className="ubuntu-file"><FileText /><span>Port_Clearance.pdf</span></div>
            <button type="button" className="payload-file" onClick={beginIncident} aria-label="훈련용 의심 파일 실행"><span className="pdf-badge">PDF</span><FileWarning /><span>Voyage_Safety_<br />Notice.pdf.run</span><small>Downloaded 09:42</small></button>
          </div>
          <footer><span>4 items</span><strong>TRAINING SERVER · ISOLATED</strong></footer>
        </article> : <article className="ubuntu-recovery-terminal">
          <header><div><Terminal /><span>root@space-xship: ~/incident-response</span></div><button type="button" aria-label="Back to bridge" onClick={() => setServerOpen(false)}><X /></button></header>
          <div className="terminal-log"><span>[CRITICAL] Integrated Bridge network heartbeat lost</span><span>[FAILED] radar-01.service · navigation-data.service</span><span>[LOCKED] ECDIS-01 · CONNING-01 · PROP-01 · ALARM-IAS</span><span>[READY] Offline recovery controller mounted</span></div>
          <div className="server-ransom-card"><Skull /><span>HAEYANG LOCKER · RECOVERY CONSOLE</span><strong>BRIDGE NETWORK ENCRYPTED</strong><p>Use the authorized recovery key to unlock all simulated bridge workstations.</p><form onSubmit={recover}><label htmlFor="server-recovery-key">RECOVERY KEY</label><div><Input id="server-recovery-key" type="password" value={recoveryKey} onChange={(event) => { setRecoveryKey(event.target.value); setRecoveryError(''); }} autoComplete="off" placeholder="Enter recovery key" /><Button type="submit" variant="destructive"><RotateCcw /> Restore bridge</Button></div>{recoveryError && <output aria-live="polite">{recoveryError}</output>}</form></div>
          <footer>ISOLATED TRAINING HOST · NO LIVE VESSEL CONNECTION</footer>
        </article>}
        {phase === 0 && <div className="ubuntu-hint"><AlertTriangle /> Open the newly downloaded voyage safety notice</div>}
      </section>}

    </main>
  );
}
