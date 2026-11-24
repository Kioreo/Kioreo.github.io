"use strict";

const $ = (id) => document.getElementById(id);
const FILES = [
  { name: "2026_항차계획_최종.pdf", type: "PDF", detail: "운항 계획 · 2.4 MB", icon: "▣" },
  { name: "기관실_교대점검표.xlsx", type: "XLSX", detail: "기관실 점검 · 680 KB", icon: "▦" },
  { name: "ECDIS_해도백업.zip", type: "ZIP", detail: "전자해도 백업 · 18.2 MB", icon: "▤" },
  { name: "항차계획_동기화.exe", type: "EXE", detail: "육상 운항센터 전달 · 실행 파일", icon: "⬡", featured: true },
  { name: "선내_안전관리_절차.pdf", type: "PDF", detail: "안전 관리 · 1.1 MB", icon: "▣" },
];
const LOCK_KEY = "hspace-maritime-ransomware-v1";
const PASSWORD_DIGEST = "0e1d1e8830347f97aa6323eb5a1f56b12a2df5af87dab59bf15be773bd3a6bfb";
const PASSWORD_FALLBACK = 0x187b2713;
let infected = sessionStorage.getItem(LOCK_KEY) === "locked";
let currentState = null;
let lastSample = 0;
let feedError = "";

function clock() { $("clock").textContent = new Date().toLocaleTimeString("ko-KR", { hour12: false }); }
clock(); setInterval(clock, 1000);
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(node => node.classList.toggle("active", node === button));
  document.querySelectorAll(".view").forEach(node => node.classList.toggle("active", node.id === button.dataset.tab));
  if (button.dataset.tab === "gnss") drawChart();
}));

function renderFiles() {
  $("file-list").replaceChildren(...FILES.map(file => {
    const row = document.createElement("button"); row.type = "button";
    row.className = `file-row${file.featured ? " featured" : ""}${infected ? " locked" : ""}`;
    const name = document.createElement("span"); name.className = "file-name";
    const icon = document.createElement("em"); icon.textContent = infected ? "▣" : file.icon;
    const labels = document.createElement("span");
    const title = document.createElement("strong"); title.textContent = infected ? `${file.name}.locked` : file.name;
    const detail = document.createElement("small"); detail.textContent = infected ? "접근 권한 없음" : file.detail;
    labels.append(title, detail); name.append(icon, labels);
    const type = document.createElement("span"); type.className = "file-type"; type.textContent = file.type;
    const open = document.createElement("span"); open.className = "file-open"; open.textContent = infected ? "잠김" : file.featured ? "실행 →" : "열기 →";
    row.append(name, type, open);
    row.addEventListener("click", () => openFile(file));
    return row;
  }));
}
function renderRansom() {
  renderFiles();
  $("ship-status").textContent = infected ? "● 주요 시스템 접근 차단" : "● 모든 시스템 정상";
  $("ship-status").className = `status ${infected ? "bad" : "good"}`;
  $("ransom-banner").textContent = infected ? "경고 · 항해 문서와 운항 기능이 잠겼습니다" : "운항 자료 동기화 완료 · 모든 장비 정상";
  $("ransom-banner").classList.toggle("bad", infected);
  $("systems").classList.toggle("infected", infected);
  $("systems").querySelectorAll("strong").forEach(node => node.textContent = infected ? "LOCKED" : ({ ECDIS: "ONLINE", "항해 계획": "READY", "기관 제어": "NORMAL", "통신 상태": "CONNECTED" })[node.previousElementSibling.textContent]);
  $("ransom-event").textContent = infected ? "의심 파일 실행 후 시스템 접근 차단. 파일 또는 기능을 선택하면 복구 암호를 요구합니다." : "시스템 준비 완료. 항차 자료를 확인할 수 있습니다.";
}
function openFile(file) {
  if (infected) return showUnlock(`${file.name} 파일을 열려면 복구 비밀번호가 필요합니다.`);
  if (file.featured) {
    infected = true; sessionStorage.setItem(LOCK_KEY, "locked"); renderRansom();
    showUnlock("항차계획 동기화 파일을 실행한 뒤 시스템이 잠겼습니다. 복구 비밀번호를 입력하세요.");
  } else {
    $("ransom-event").textContent = `${file.name} 파일을 열었습니다. (교육용 가상 문서)`;
  }
}
function showUnlock(context) {
  $("dialog-context").textContent = context;
  $("unlock-error").textContent = "";
  $("unlock-password").value = "";
  $("unlock-dialog").showModal();
  $("unlock-password").focus();
}
document.querySelectorAll(".action").forEach(button => button.addEventListener("click", () => {
  const action = button.dataset.action;
  if (infected) showUnlock(`${action} 기능을 사용하려면 복구 비밀번호가 필요합니다.`);
  else $("ransom-event").textContent = `${action} 작업이 정상 완료되었습니다. (교육용 시뮬레이션)`;
}));
$("local-reset").addEventListener("click", () => {
  if (infected) return showUnlock("화면을 초기화하려면 복구 비밀번호가 필요합니다.");
  $("ransom-event").textContent = "화면 상태를 초기화했습니다.";
});
$("cancel-unlock").addEventListener("click", () => $("unlock-dialog").close());
$("unlock-form").addEventListener("submit", async event => {
  event.preventDefault();
  const bytes = new TextEncoder().encode($("unlock-password").value);
  let valid;
  if (crypto.subtle) {
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(x => x.toString(16).padStart(2, "0")).join("");
    valid = digest === PASSWORD_DIGEST;
  } else {
    let hash = 2166136261;
    for (const byte of bytes) hash = Math.imul(hash ^ byte, 16777619) >>> 0;
    valid = hash === PASSWORD_FALLBACK;
  }
  if (!valid) {
    $("unlock-error").textContent = "비밀번호가 일치하지 않습니다.";
    $("unlock-password").select(); return;
  }
  infected = false; sessionStorage.removeItem(LOCK_KEY); renderRansom();
  $("ransom-event").textContent = "복구 비밀번호 확인 완료. 선박 운항 화면이 정상으로 돌아왔습니다.";
  $("unlock-dialog").close();
});
renderRansom();

function text(id, value) { $(id).textContent = value; }
function number(value, digits = 1) { return typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "—"; }
function showFeedStatus(label, kind) { const node = $("feed-status"); node.textContent = `● ${label}`; node.className = `status ${kind}`; }
function renderGNSS(state) {
  const phase = state.phase || "baseline";
  const source = state.selected_source || "—";
  const metric = state.metrics || {};
  const turn = state.turn_effect || {};
  const phaseInfo = phase === "deviating"
    ? ["ROUTE DEVIATION", "실제 항로 이탈", "자동조타가 변조 GNSS를 따라 선체를 움직이고 있습니다."]
    : phase === "attack"
      ? ["GNSS MANIPULATION", "GNSS 변조 감지", "GPS 2의 왜곡된 위치가 선택되거나 주입되고 있습니다."]
      : ["NORMAL NAVIGATION", "정상 항해", "GPS 1을 기준으로 계획 항로를 따라 항해 중입니다."];
  $("phase-card").className = `phase-card ${phase === "baseline" ? "normal" : phase}`;
  text("phase-kicker", phaseInfo[0]); text("phase-title", phaseInfo[1]); text("phase-desc", phaseInfo[2]);
  showFeedStatus(phase === "deviating" ? "실제 항로 이탈" : phase === "attack" ? "GNSS 변조 진행" : "정상 항해 중", phase === "deviating" ? "bad" : phase === "attack" ? "attack" : "good");
  text("source", source); text("xte", `${number(metric.actual_xte_m)} m`); text("bias", `${number(metric.gps_bias_m)} m`);
  text("heading", `${number(turn.heading_delta_since_attack_deg)}°`); text("rudder", `${number(turn.rudder_command_deg)}°`);
  text("sample-time", `SAMPLE ${new Date(state.timestamp_ms || Date.now()).toLocaleTimeString("ko-KR", {hour12:false})}`);
  const steps = [...$("steps").children];
  const selectedAux = source.includes("aux");
  steps.forEach((node, i) => { node.className = i === 0 ? "done" : (i === 1 && phase !== "baseline") || (i === 2 && selectedAux) || (i === 3 && phase === "deviating") ? "active" : ""; });
  text("gnss-event", phase === "deviating" ? `실제 선체 이탈 ${number(metric.actual_xte_m)} m · GNSS 보고 위치 편차 ${number(metric.gps_bias_m)} m` : phase === "attack" ? `GNSS 소스 ${source} · 편차 ${number(metric.gps_bias_m)} m` : `정상 소스 ${source} · 계획 항로 추적 중`);
  $("chart-empty").hidden = true;
  drawChart();
}
function point(p) { return p && Number.isFinite(Number(p.latitude)) && Number.isFinite(Number(p.longitude)) ? {lat:Number(p.latitude),lon:Number(p.longitude)} : null; }
function drawChart() {
  const canvas = $("chart"), box = canvas.getBoundingClientRect();
  if (!box.width || !box.height) return;
  const dpr = Math.min(devicePixelRatio || 1, 2); canvas.width = Math.round(box.width*dpr); canvas.height = Math.round(box.height*dpr);
  const ctx = canvas.getContext("2d"); ctx.scale(dpr,dpr);
  const w=box.width,h=box.height;
  ctx.fillStyle="#0a2636"; ctx.fillRect(0,0,w,h);
  ctx.strokeStyle="#1d485e"; ctx.lineWidth=1;
  for(let x=0;x<w;x+=44){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke()}
  for(let y=0;y<h;y+=44){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  ctx.strokeStyle="#28667b";ctx.setLineDash([2,9]);
  for(let x=22;x<w;x+=176){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke()}
  ctx.setLineDash([]);
  const state=currentState, actual=point(state?.positions?.actual || state?.actual_position);
  if(!actual) return;
  const report=point(state?.positions?.reported || state?.reported_position);
  const cos=Math.cos(actual.lat*Math.PI/180);
  const toM=p=>({x:(p.lon-actual.lon)*111320*cos,y:(p.lat-actual.lat)*111320});
  const xte=Math.abs(Number(state?.metrics?.actual_xte_m)||0);
  const scale=Math.max(1.05,xte/Math.max(h*.32,1));
  const px=p=>({x:w*.44+p.x/scale,y:h*.53-p.y/scale});
  const line=(points,color,width,dash=[])=>{if(points.length<2)return;ctx.beginPath();points.forEach((p,i)=>{const q=px(p);i?ctx.lineTo(q.x,q.y):ctx.moveTo(q.x,q.y)});ctx.strokeStyle=color;ctx.lineWidth=width;ctx.setLineDash(dash);ctx.stroke();ctx.setLineDash([])};
  const route=state.route || {},start=point(route.start),way=point(route.waypoint);
  if(start&&way){const a=toM(start),b=toM(way),vx=b.x-a.x,vy=b.y-a.y,l=Math.hypot(vx,vy)||1,ux=vx/l,uy=vy/l,t=-(a.x*ux+a.y*uy);line([{x:a.x+(t-2000)*ux,y:a.y+(t-2000)*uy},{x:a.x+(t+2000)*ux,y:a.y+(t+2000)*uy}],"#48b6fa",3,[12,9]);}
  const track=(state.actual_track||[]).map(point).filter(Boolean).map(toM).filter(p=>Math.abs(p.x)<w*scale*1.5&&Math.abs(p.y)<h*scale*1.5);
  line(track,"#35debe",3);
  if(report){const r=toM(report);if(Math.hypot(r.x,r.y)>2){line([{x:0,y:0},r],"#f5b75d",1.5,[4,6]);const q=px(r);ctx.strokeStyle="#f5b75d";ctx.lineWidth=2;ctx.beginPath();ctx.arc(q.x,q.y,9,0,Math.PI*2);ctx.stroke();ctx.fillStyle="#f5b75d";ctx.font="10px ui-monospace, monospace";ctx.fillText("GNSS",q.x+13,q.y-8);}}
  const ship=px({x:0,y:0});const heading=Number(state?.turn_effect?.heading_deg ?? state?.physics?.heading ?? 90)*Math.PI/180;
  ctx.save();ctx.translate(ship.x,ship.y);ctx.rotate(heading);ctx.fillStyle="#35debe";ctx.shadowColor="#35debe";ctx.shadowBlur=19;ctx.beginPath();ctx.moveTo(0,-18);ctx.lineTo(11,14);ctx.lineTo(0,7);ctx.lineTo(-11,14);ctx.closePath();ctx.fill();ctx.restore();
  ctx.fillStyle="#d3f8ed";ctx.font="11px ui-monospace, monospace";ctx.fillText("ACTUAL SHIP",ship.x+18,ship.y+20);
  ctx.fillStyle="#5e99ae";ctx.font="10px ui-monospace, monospace";ctx.fillText(`${actual.lat.toFixed(6)}° N  ${actual.lon.toFixed(6)}° E`,w-235,h-21);
}
new ResizeObserver(drawChart).observe($("chart"));

const requestedFeed = new URL(location.href).searchParams.get("feed");
let stateUrl = window.MARITIME_CONFIG?.stateUrl || "/api/state";
if (requestedFeed) {
  try {
    const feed = new URL(requestedFeed);
    if (feed.protocol === "https:" && feed.pathname === "/api/state" && !feed.username && !feed.password) stateUrl = feed.href;
  } catch { /* Keep configured feed. */ }
}
text("api-label", stateUrl.length > 58 ? `${stateUrl.slice(0,55)}…` : stateUrl);
async function poll() {
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);
  try {
    const headers={}; if(new URL(stateUrl,location.href).hostname.endsWith("ngrok-free.dev")) headers["ngrok-skip-browser-warning"]="maritime-demo";
    const response=await fetch(stateUrl,{cache:"no-store",signal:controller.signal,headers});
    if(!response.ok)throw Error(`HTTP ${response.status}`);
    const state=await response.json();
    if(!state || !point(state?.positions?.actual || state?.actual_position))throw Error("위치 데이터 없음");
    currentState=state; lastSample=Date.now(); feedError=""; renderGNSS(state);
  } catch(error) { feedError=error.message || "연결 실패"; if(Date.now()-lastSample>6000){showFeedStatus("데이터 연결 대기","waiting");text("gnss-event",`실습 서버 연결 대기: ${feedError}`);$("chart-empty").hidden=false;}}
  finally { clearTimeout(timer); }
}
poll(); setInterval(poll,1500);
