(function(){
'use strict';

const CTRL_RE = /[^\x20-\x7E\u00A0-\uFFFF]/g;
function san(str, max){ return String(str||'').replace(CTRL_RE,'').slice(0, max||200); }
function esc(str){ return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

const IP_RE     = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

let currentData = null;

function showError(msg){ const el=document.getElementById('errorBox'); el.textContent='// '+san(msg,200); el.classList.add('show'); }
function hideError(){ document.getElementById('errorBox').classList.remove('show'); }
function setLoading(msg){ const lb=document.getElementById('loadingBlock'); lb.classList.add('show'); document.getElementById('loadingText').textContent='// '+san(msg||'Querying...',100); }
function hideLoading(){ document.getElementById('loadingBlock').classList.remove('show'); }
function setVal(id, val, cls){ const el=document.getElementById(id); if(!el) return; el.textContent=san(String(val||'—'),200); if(cls) el.className='val '+cls; }
function setThreat(id, val){ const el=document.getElementById(id); if(!el) return; el.textContent=val?'YES':'NO'; el.className='threat-val '+(val?'t-yes':'t-no'); }

function countryFlag(code){
  if(!code||code.length!==2) return '';
  try{ return String.fromCodePoint(...[...code.toUpperCase()].map(c=>0x1F1E6-65+c.charCodeAt(0))); }catch{ return ''; }
}

function renderMap(lat, lon){
  const wrap=document.getElementById('mapWrap');
  const noCoords=document.getElementById('mapNoCoords');
  wrap.innerHTML=''; wrap.appendChild(noCoords);
  if(lat == null || lon == null){ noCoords.style.display=''; return; }
  noCoords.style.display='none';

  // create map container
  const mapDiv=document.createElement('div');
  mapDiv.id='leafletMap';
  mapDiv.style.cssText='width:100%;height:100%;';
  wrap.appendChild(mapDiv);

  // load leaflet if not already loaded
  function initLeaflet(){
    const map=L.map('leafletMap',{zoomControl:true,attributionControl:true}).setView([lat,lon],6);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
      attribution:'&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
      subdomains:'abcd', maxZoom:19
    }).addTo(map);
    // custom red marker
    const icon=L.divIcon({className:'',html:`<div style="width:14px;height:14px;background:#e8000f;border:2px solid rgba(232,0,15,0.4);border-radius:50%;box-shadow:0 0 12px rgba(232,0,15,0.8);"></div>`,iconSize:[14,14],iconAnchor:[7,7]});
    L.marker([lat,lon],{icon}).addTo(map);
  }

  if(window.L){
    initLeaflet();
  } else {
    const css=document.createElement('link'); css.rel='stylesheet'; css.href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'; document.head.appendChild(css);
    const js=document.createElement('script'); js.src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    js.onload=initLeaflet; document.head.appendChild(js);
  }
}

function renderResults(d){
  const flag = countryFlag(d.countryCode);
  setVal('rIp', d.ip, 'w');
  setVal('rCountry',  d.country + (flag ? ' '+flag : ''));
  setVal('rRegion',   d.region);
  setVal('rCity',     d.city);
  setVal('rPostal',   d.postal);
  setVal('rTimezone', d.tz);
  setVal('rLocalTime',d.localTime);
  setVal('rCoords',   d.lat && d.lon ? `${Number(d.lat).toFixed(4)}, ${Number(d.lon).toFixed(4)}` : '—');
  setVal('rIsp',      d.isp, 'w');
  setVal('rOrg',      d.org);
  setVal('rAsn',      d.asn);
  setVal('rAsname',   d.asname);
  setVal('rVersion',  d.isIPv6 ? 'IPv6' : 'IPv4');
  setVal('rRdns',     d.rdns);
  setVal('rEu',       d.eu===true?'Yes':d.eu===false?'No':'—');
  setVal('rCurrency', d.currency);
  setVal('rLanguages',d.languages);
  setVal('rCalling',  d.calling ? '+'+d.calling : '—');
  setVal('rContinent',d.continent);
  setVal('rCapital',  d.capital);

  let badges='';
  if(d.isVpn)    badges+=`<span class="badge b-vpn">VPN</span>`;
  if(d.isTor)    badges+=`<span class="badge b-tor">TOR</span>`;
  if(d.isProxy)  badges+=`<span class="badge b-proxy">PROXY</span>`;
  if(d.isHosting)badges+=`<span class="badge b-hosting">HOSTING</span>`;
  if(d.mobile)   badges+=`<span class="badge b-mobile">MOBILE</span>`;
  if(!d.isVpn&&!d.isTor&&!d.isProxy&&!d.isHosting&&!d.mobile) badges+=`<span class="badge b-residential">RESIDENTIAL</span>`;
  if(d.isIPv6)   badges+=`<span class="badge b-v6">IPv6</span>`;
  document.getElementById('rBadges').innerHTML = badges;

  setThreat('tVpn',         !!d.isVpn);
  setThreat('tTor',         !!d.isTor);
  setThreat('tProxy',       !!d.isProxy);
  setThreat('tHosting',     !!d.isHosting);
  setThreat('tMobile',      !!d.mobile);
  setThreat('tResidential', !d.isVpn&&!d.isTor&&!d.isProxy&&!d.isHosting);

  renderMap(d.lat, d.lon);
  document.getElementById('resultBlock').classList.add('show');
  document.getElementById('resultBlock').scrollIntoView({ behavior:'smooth', block:'start' });
}

async function doLookup(target){
  const scanBtn=document.getElementById('scanBtn');
  if(scanBtn) scanBtn.disabled=true;
  hideError();
  document.getElementById('resultBlock').classList.remove('show');
  setLoading('Sending to intelligence server...');
  try {
    const res = await fetch('/api/ip', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data.error||'Lookup failed');
    currentData = data;
    renderResults(data);
  } catch(err){
    showError(san(err.message,200));
  } finally {
    hideLoading();
    if(scanBtn) scanBtn.disabled=false;
  }
}

async function handleScan(){
  let raw = document.getElementById('ipInput').value.trim()
    .replace(/^https?:\/\//i,'').replace(/\/.*$/,'').replace(/^www\./i,'').trim();
  if(!raw){ showError('Please enter an IP address or domain.'); return; }
  if(!IP_RE.test(raw) && !DOMAIN_RE.test(raw)){ showError('Invalid IP address or domain format.'); return; }
  await doLookup(raw);
}

async function handleMyIp(){
  const btn=document.getElementById('myIpBtn');
  if(btn){ btn.disabled=true; btn.textContent='⬡ Detecting...'; }
  hideError();
  setLoading('Detecting your public IP...');
  try {
    const res  = await fetch('/api/ip', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ target:'self' }) });
    const data = await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data.error||'Could not detect IP');
    document.getElementById('ipInput').value = data.ip || '';
    currentData = data;
    renderResults(data);
  } catch(err){
    showError(san(err.message,200));
  } finally {
    hideLoading();
    if(btn){ btn.disabled=false; btn.textContent='⬡ Analyze My IP'; }
  }
}

function handleCopy(){
  if(!currentData) return;
  const d=currentData;
  const text=[
    'AntiSec IP Intelligence Report',
    '================================',
    `IP:          ${d.ip}`,
    `Country:     ${d.country} (${d.countryCode})`,
    `Region:      ${d.region}`,
    `City:        ${d.city}`,
    `Postal:      ${d.postal}`,
    `Timezone:    ${d.tz}`,
    `Local Time:  ${d.localTime}`,
    `Coordinates: ${d.lat}, ${d.lon}`,
    `ISP:         ${d.isp}`,
    `Org:         ${d.org}`,
    `ASN:         ${d.asn}`,
    `AS Name:     ${d.asname}`,
    `rDNS:        ${d.rdns}`,
    `Version:     ${d.isIPv6?'IPv6':'IPv4'}`,
    `Currency:    ${d.currency}`,
    `Languages:   ${d.languages}`,
    `Calling:     +${d.calling}`,
    `Continent:   ${d.continent}`,
    `Capital:     ${d.capital}`,
    `EU:          ${d.eu?'Yes':'No'}`,
    '',
    'Threat Intelligence',
    `VPN:         ${d.isVpn?'YES':'No'}`,
    `Tor:         ${d.isTor?'YES':'No'}`,
    `Proxy:       ${d.isProxy?'YES':'No'}`,
    `Hosting:     ${d.isHosting?'YES':'No'}`,
    `Mobile:      ${d.mobile?'Yes':'No'}`,
    '',
    `Generated: ${new Date().toISOString()}`,
  ].join('\n');
  navigator.clipboard.writeText(text).then(()=>{
    const b=document.getElementById('btnCopy'); const o=b.textContent; b.textContent='✓ Copied!'; setTimeout(()=>b.textContent=o,2000);
  }).catch(()=>{});
}

function handleJson(){
  if(!currentData) return;
  const blob=new Blob([JSON.stringify(currentData,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url;
  a.download=`ip_intel_${san(currentData.ip||'unknown',45).replace(/[^a-zA-Z0-9.\-]/g,'_')}_${new Date().toISOString().slice(0,10)}.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}

function handleNew(){
  document.getElementById('resultBlock').classList.remove('show');
  document.getElementById('ipInput').value='';
  hideError(); hideLoading(); currentData=null;
  document.getElementById('ipInput').focus();
}

window.addEventListener('DOMContentLoaded', function(){
  document.getElementById('scanBtn').addEventListener('click', handleScan);
  document.getElementById('myIpBtn').addEventListener('click', handleMyIp);
  document.getElementById('ipInput').addEventListener('keydown', e=>{ if(e.key==='Enter') handleScan(); });
  document.getElementById('btnCopy').addEventListener('click', handleCopy);
  document.getElementById('btnJson').addEventListener('click', handleJson);
  document.getElementById('btnNew').addEventListener('click', handleNew);

  let inviteUrl = '';
  fetch('/api/config').then(r => r.json()).then(function(d){
    inviteUrl = san(d.invite || '', 200);
    const join1 = document.getElementById('joinServerBtn');
    const join2 = document.getElementById('ctaJoinBtn');
    if (inviteUrl) {
      if (join1) join1.href = inviteUrl;
      if (join2) join2.href = inviteUrl;
    } else {
      if (join1) join1.querySelector('.sidebar-sub').textContent = '// link unavailable';
    }
  }).catch(function(){});

  const hamburger = document.getElementById('hamburgerBtn');
  const sidebar    = document.getElementById('sidebar');
  const overlay    = document.getElementById('sidebarOverlay');

  function openSidebar(){ hamburger.classList.add('open'); sidebar.classList.add('show'); overlay.classList.add('show'); }
  function closeSidebar(){ hamburger.classList.remove('open'); sidebar.classList.remove('show'); overlay.classList.remove('show'); }

  hamburger.addEventListener('click', function(){
    if (sidebar.classList.contains('show')) closeSidebar(); else openSidebar();
  });
  overlay.addEventListener('click', closeSidebar);

  const howToBtn   = document.getElementById('howToBtn');
  const howToModal = document.getElementById('howToModal');
  const howToClose = document.getElementById('howToClose');

  howToBtn.addEventListener('click', function(){
    closeSidebar();
    howToModal.classList.add('show');
  });
  howToClose.addEventListener('click', function(){ howToModal.classList.remove('show'); });
  howToModal.addEventListener('click', function(e){ if (e.target === howToModal) howToModal.classList.remove('show'); });

  const faqBtn   = document.getElementById('faqBtn');
  const faqModal = document.getElementById('faqModal');
  const faqClose = document.getElementById('faqClose');

  faqBtn.addEventListener('click', function(){
    closeSidebar();
    faqModal.classList.add('show');
  });
  faqClose.addEventListener('click', function(){ faqModal.classList.remove('show'); });
  faqModal.addEventListener('click', function(e){ if (e.target === faqModal) faqModal.classList.remove('show'); });

  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape') { closeSidebar(); howToModal.classList.remove('show'); faqModal.classList.remove('show'); }
  });
});

})();
