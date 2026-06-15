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
  const ns='http://www.w3.org/2000/svg';
  const svg=document.createElementNS(ns,'svg'); svg.setAttribute('viewBox','0 0 1000 500'); svg.style.cssText='width:100%;height:100%;display:block';
  const bg=document.createElementNS(ns,'rect'); bg.setAttribute('width','1000'); bg.setAttribute('height','500'); bg.setAttribute('fill','#010101'); svg.appendChild(bg);
  const g=document.createElementNS(ns,'g'); g.setAttribute('stroke','#080808'); g.setAttribute('stroke-width','0.5');
  for(let x=0;x<=1000;x+=100){const l=document.createElementNS(ns,'line');l.setAttribute('x1',x);l.setAttribute('y1',0);l.setAttribute('x2',x);l.setAttribute('y2',500);g.appendChild(l);}
  for(let y=0;y<=500;y+=50){const l=document.createElementNS(ns,'line');l.setAttribute('x1',0);l.setAttribute('y1',y);l.setAttribute('x2',1000);l.setAttribute('y2',y);g.appendChild(l);}
  svg.appendChild(g);
  const x=((lon+180)/360)*1000, y=((90-lat)/180)*500;
  const hl=document.createElementNS(ns,'line'); hl.setAttribute('x1','0');hl.setAttribute('y1',y);hl.setAttribute('x2','1000');hl.setAttribute('y2',y);hl.setAttribute('stroke','rgba(232,0,15,0.08)');hl.setAttribute('stroke-width','0.5'); svg.appendChild(hl);
  const vl=document.createElementNS(ns,'line'); vl.setAttribute('x1',x);vl.setAttribute('y1','0');vl.setAttribute('x2',x);vl.setAttribute('y2','500');vl.setAttribute('stroke','rgba(232,0,15,0.08)');vl.setAttribute('stroke-width','0.5'); svg.appendChild(vl);
  const ring=document.createElementNS(ns,'circle'); ring.setAttribute('cx',x);ring.setAttribute('cy',y);ring.setAttribute('r','20');ring.setAttribute('fill','none');ring.setAttribute('stroke','rgba(232,0,15,0.3)');ring.setAttribute('stroke-width','1'); svg.appendChild(ring);
  const dot=document.createElementNS(ns,'circle'); dot.setAttribute('cx',x);dot.setAttribute('cy',y);dot.setAttribute('r','5');dot.setAttribute('fill','#e8000f'); svg.appendChild(dot);
  wrap.appendChild(svg);
  let s=1,dir=1,f=0;
  function step(){ f++; s+=dir*0.02; if(s>1.5)dir=-1; if(s<0.7)dir=1; ring.setAttribute('r',20*s); ring.setAttribute('opacity',String(1.8-s)); if(f<400)requestAnimationFrame(step); }
  requestAnimationFrame(step);
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
});

})();
