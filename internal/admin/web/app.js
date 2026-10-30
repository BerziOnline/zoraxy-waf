'use strict';
import {bars, donut, ring, ranking, spark, PALETTE, fmt} from './charts.js';
const $ = id => document.getElementById(id);
// Follow Zoraxy's theme switch (same-origin localStorage key written by darktheme.js).
function applyTheme() { document.documentElement.classList.toggle('dark', localStorage.getItem('theme') === 'dark'); }
applyTheme(); window.addEventListener('storage', e => { if (e.key === 'theme') applyTheme(); });
// Jump to a Zoraxy tab from inside the sandboxed plugin iframe (same origin, no top navigation allowed).
function zoraxyTab(id) { try { if (window.parent && window.parent !== window && typeof window.parent.openTabById === 'function') { window.parent.openTabById(id); return; } } catch (e) {} notice('Open Zoraxy → ' + id + ' from the main menu (this plugin runs standalone here).'); }
document.querySelectorAll('[data-zoraxy-tab]').forEach(b => b.addEventListener('click', () => zoraxyTab(b.dataset.zoraxyTab)));
const csrf = document.querySelector('meta[name="waf-csrf"]').content;
let config, capabilities, eventRows = [], exceptionID = '', busy = false, dirty = false;
const val = id => $(id).value;
const num = id => Number(val(id));
const clone = () => structuredClone(config);
function notice(message, error = false) { $('notice').textContent = message; $('notice').className = 'ui ' + (error ? 'negative ' : 'positive ') + 'message'; $('notice').setAttribute('role', error ? 'alert' : 'status'); if (error) $('notice').scrollIntoView({block: 'nearest'}); }
async function api(path, options = {}) {
 const response = await fetch(path, {credentials: 'same-origin', ...options, headers: {'Content-Type':'application/json','X-CSRF-Token':csrf,'X-WAF-CSRF':csrf, ...options.headers}});
 if (!response.ok) throw new Error(await response.text());
 return response.json();
}
function tab(id) { document.querySelectorAll('.tab').forEach(s => s.hidden = s.id !== id); document.querySelectorAll('[data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === id)); }
document.querySelectorAll('[data-tab]').forEach(b => b.addEventListener('click', () => tab(b.dataset.tab)));
function localDate(date) { const d = new Date(date); return new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0,16); }
function setCapabilities(selected = config.engine) {
 const same = selected === config.engine;
 const supportsPL = same ? capabilities.paranoia_levels : selected === 'coraza';
 const supportsExceptions = same ? capabilities.rule_exclusions : selected === 'coraza';
 $('coraza-settings').hidden = !supportsPL; $('crowdsec-settings').hidden = selected !== 'crowdsec';
 // Host/exception forms edit the active engine, not the unsaved selector.
 $('host-pl-field').hidden = !capabilities.paranoia_levels;
 $('exception-form').hidden = !capabilities.rule_exclusions;
 $('exception-unsupported').hidden = capabilities.rule_exclusions;
 $('paranoia').disabled = !supportsPL; $('threshold').disabled = !supportsPL;
 return supportsExceptions;
}
let sinks = [];
function renderSinks() {
 table('sinks', ['Name', 'Format', 'URL', 'Token', ''], sinks.map((k, i) => [k.name || k.id, k.format, k.url, k.token ? 'stored' : '–', button('Remove', () => { sinks.splice(i, 1); renderSinks(); })]));
}
function fillAlerts() {
 const a = config.alerts; sinks = structuredClone(a.sinks || []); renderSinks();
 $('alerts-enabled').checked = a.enabled; $('alerts-engine').checked = a.engine_health;
 for (const [id, v] of Object.entries({'alerts-burst': a.burst_count, 'alerts-window': a.burst_window_min, 'alerts-expiry': a.exception_expiry_days, 'alerts-cooldown': a.cooldown_min})) $(id).value = v;
}
function renderAlertStats(st) { if (!st) return; $('alerts-status').textContent = `Delivered ${fmt(st.Sent)} · failed ${fmt(st.Failed)}` + (st.LastSentAt && st.LastSentAt !== '0001-01-01T00:00:00Z' ? ` · last ${new Date(st.LastSentAt).toLocaleString()}` : '') + (st.LastError ? ` · last error: ${st.LastError}` : ''); }
$('sink-add').addEventListener('click', () => {
 const url = val('sink-url').trim(); if (!/^https?:\/\//.test(url)) { notice('Receiver URL must start with http:// or https://', true); return; }
 sinks.push({id: Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join(''), name: val('sink-name').trim() || 'receiver', format: val('sink-format'), url, token: val('sink-token')});
 for (const id of ['sink-name', 'sink-url', 'sink-token']) $(id).value = ''; renderSinks(); dirty = true;
});
onForm('alerts-form', async () => {
 const c = clone();
 c.alerts = {enabled: $('alerts-enabled').checked, engine_health: $('alerts-engine').checked, burst_count: num('alerts-burst'), burst_window_min: num('alerts-window'), exception_expiry_days: num('alerts-expiry'), cooldown_min: num('alerts-cooldown'), sinks: sinks.map(k => ({id: k.id, name: k.name, format: k.format, url: k.url, token: k.token || ''}))};
 if (c.alerts.enabled && !c.alerts.sinks.length) throw new Error('Add at least one receiver before enabling alerts.');
 await save(c); fillAlerts();
});
$('alerts-test').addEventListener('click', async () => { try { const st = await api('api/alerts/test', {method: 'POST', body: '{}'}); renderAlertStats(st); notice('Test alert delivered to every receiver.'); } catch (e) { notice(e.message, true); } });
function fillSettings() {
 fillAlerts();
 const c = config;
 for (const [id, value] of Object.entries({'engine':c.engine,'mode':c.mode,'max-body':c.max_body_kb,'body-timeout':c.body_timeout_ms,'max-concurrent':c.max_concurrent,'paranoia':c.coraza.paranoia_level,'threshold':c.coraza.anomaly_threshold,'appsec-url':c.crowdsec.url,'appsec-timeout':c.crowdsec.timeout_ms,'ring-size':c.events.ring_size,'max-file':c.events.max_file_kb,'max-files':c.events.max_files})) $(id).value=value;
 $('appsec-key').value=''; $('fail-closed').checked=c.fail_closed; for(const r of document.querySelectorAll('input[name="gc-target"]')) r.checked=Number(r.value)===c.gc_target; $('failure-hosts').value=c.invert_failure_hosts.join('\n'); dirty=false; setCapabilities();
}
function renderSpeed(state) {
 // The chosen level sets the plugin's own GC target at once. Only GOGC=off on the
 // Zoraxy service is respected (never re-enabled); Zoraxy's own GC is not touched.
 const gc=state.gc_percent, want=config.gc_target, note=$('speed-inactive');
 $('speed-active').textContent=gc<0?'':`Active now: level ${gc}.`;
 note.hidden=gc===want;
 note.textContent=gc<0?'Speed has no effect: garbage collection is disabled for this process (GOGC=off on the Zoraxy service).':`Saved level ${want} is not active yet (running: ${gc}). Save again or restart the plugin.`;
 $('speed-cores').querySelector('strong').textContent=`CPU cores (${state.cpu_cores} available now):`;
}
function renderHealth(state) {
 if (state.load_error) notice(state.load_error,true);
 renderSpeed(state);
 renderAlertStats(state.alert_stats);
 const e=state.event_stats;$('feed-line').textContent=`JSONL feed: ${fmt(e.written)} written · ${fmt(e.dropped)} dropped · ${fmt(e.write_errors)} write errors · ${fmt(e.buffered)} queued. Retention changes require restart.`;
}
const HOUR = {hour:'numeric'}, DAY = {day:'2-digit', month:'2-digit'};
const narrow = () => ($('chart-hours').clientWidth || 600) < 480;
function renderOverview(sum) {
 lastSummary = sum;
 const h = sum.history, hero = $('hero');
 const state = !sum.health.Engine.ok ? 'bad' : sum.mode === 'block' ? 'ok' : sum.mode === 'report' ? 'warn' : 'off';
 hero.className = 'hero state-' + state;
 $('hero-headline').textContent = state === 'bad' ? 'Engine problem' : state === 'ok' ? 'Blocking attacks' : state === 'warn' ? 'Learning mode: attacks are recorded, not blocked' : 'Inspection is off';
 const rs = sum.health.Engine.rule_set ? ' · ' + sum.health.Engine.rule_set : '';
 const hostNote = sum.hosts_block.length + sum.hosts_report.length + sum.hosts_off.length ? ` · host overrides: ${sum.hosts_block.length} block, ${sum.hosts_report.length} report, ${sum.hosts_off.length} off` : '';
 $('hero-sub').textContent = `${sum.health.EngineName}${rs} · revision ${sum.health.Revision}${hostNote}` + (state === 'bad' ? ' · ' + sum.health.Engine.detail : '');
 const hourly = h.hours.map(p => p.blocked + p.would_block); $('hero-spark').hidden = hourly.filter(Boolean).length < 2; spark($('hero-spark'), hourly, '#ffffff');
 const attacks = c => c.blocked + c.would_block;
 $('hm-today').textContent = fmt(attacks(h.today));
 const days = Math.min(h.days_known, 7);
 $('hm-today-note').textContent = days ? `Ø ${((attacks(h.d7) - attacks(h.today)) / days).toFixed(1)} per day · last ${days} full day${days > 1 ? 's' : ''}` : 'no full day recorded yet';
 $('hm-blocked').textContent = fmt(h.h24.blocked);
 $('hm-recorded').textContent = fmt(h.h24.would_block);
 $('hm-p95').textContent = sum.stats.LatencyP95MS ? sum.stats.LatencyP95MS.toFixed(2) + ' ms' : '–';
 // Protection ring + checklist (each missing item links to its tab).
 const score = sum.protection.score;
 ring($('protection-ring'), score, score >= 85 ? '#21ba45' : score >= 50 ? '#FBBF0F' : '#E02424');
 const list = $('protection-list'); list.replaceChildren();
 for (const it of sum.protection.items) {
  const li = document.createElement('li'); li.className = it.ok ? 'ok' : 'missing'; li.append(it.label);
  if (!it.ok) { const b = document.createElement('button'); b.type = 'button'; b.className = 'linkish'; b.textContent = 'Fix'; b.addEventListener('click', () => tab(it.tab)); li.append(b); const hint = document.createElement('span'); hint.className = 'hint'; hint.textContent = it.hint; li.append(hint); }
  list.append(li);
 }
 const series = [{name: 'blocked', color: '#3B6FF5'}, {name: 'recorded only', color: '#FBBF0F'}, {name: 'errors', color: '#E02424'}];
 const vals = c => [c.blocked, c.would_block, c.error + c.oversize];
 const n24 = bars($('chart-hours'), h.hours.map(p => ({label: new Date(p.time).toLocaleTimeString([], HOUR), values: vals(p)})), series, {every: narrow() ? 6 : 4, label: 'Attacks per hour, last 24 hours'});
 $('hours-sub').textContent = `Last 24 hours · ${fmt(n24)} events · ${fmt(h.h24.allowed)} clean requests allowed`;
 const n30 = bars($('chart-days'), h.days.map(p => ({label: new Date(p.time).toLocaleDateString([], DAY), values: vals(p)})), series, {every: narrow() ? 7 : 5, label: 'Attacks per day, last 30 days'});
 $('days-sub').textContent = h.since ? `Last 30 days · ${fmt(n30)} events · history since ${new Date(h.since).toLocaleDateString()}` : 'Last 30 days · nothing recorded yet';
 const win = sum.window.events ? `Last ${fmt(sum.window.events)} events (ring of ${fmt(sum.window.ring_size)}) since ${new Date(sum.window.oldest).toLocaleString()}` : 'No events in the live window yet';
 $('cat-sub').textContent = win;
 donut($('chart-categories'), sum.categories.map(c => ({label: c.key, value: c.count})), {label: 'Attack types', empty: 'No attacks recorded in this window'});
 ranking($('top-hosts'), sum.top_hosts, {total: sum.window.events, empty: 'No attacks on any host in this window'});
 ranking($('top-rules'), sum.top_rules.map(r => ({key: r.key, label: r.label, count: r.count})), {total: sum.window.events, empty: 'No rule fired in this window'});
 ranking($('top-ips'), sum.top_ips, {total: sum.window.events, action: r => { const b = document.createElement('button'); b.type = 'button'; b.className = 'linkish rank-action'; b.textContent = 'events'; b.title = 'Show the events of this IP'; b.addEventListener('click', () => { $('filter-ip').value = r.key; tab('events'); refreshEvents().catch(e => notice(e.message, true)); }); return b; }, empty: 'No attacking client in this window'});
 const st = sum.stats;
 donut($('chart-decisions'), [{label: 'allowed', value: st.Allowed, color: '#21ba45'}, {label: 'blocked', value: st.Blocked, color: '#3B6FF5'}, {label: 'recorded only', value: st.WouldBlock, color: '#FBBF0F'}, {label: 'errors', value: st.Errors, color: '#E02424'}, {label: 'oversize', value: st.Oversize, color: '#8B5CF6'}], {label: 'Decisions since start'});
 $('decisions-sub').textContent = `Lifetime counters of this process · ${fmt(st.Inspected)} inspected · ${fmt(st.Saturated)} over capacity · ${fmt(st.Skipped)} skipped`;
}
function button(label, fn, disabled = false) {const b=document.createElement('button');b.type='button';b.className='ui small button';b.textContent=label;b.disabled=disabled;b.addEventListener('click',()=>Promise.resolve().then(fn).catch(e=>notice(e.message,true)));return b;}
function table(id,headers,rows) {
 const t=document.createElement('table');t.className='ui compact celled table';const head=t.createTHead().insertRow();headers.forEach(h=>{const th=document.createElement('th');th.textContent=h;head.append(th);});const body=t.createTBody();
 rows.forEach(row=>{const tr=body.insertRow();row.forEach(value=>{const td=tr.insertCell();if(value instanceof Node) td.append(value);else td.textContent=String(value??'');});});
 if (!rows.length){const td=body.insertRow().insertCell();td.colSpan=headers.length;td.textContent='No entries';}$(id).replaceChildren(t);
}
function actions(...nodes) {const d=document.createElement('div');d.className='row-actions';d.append(...nodes);return d;}
function renderPolicies() {
 table('host-list',['Host / route','Mode','Body KiB','Timeout ms','Paranoia','Actions'],Object.entries(config.hosts).sort(([a],[b])=>a.localeCompare(b)).map(([key,h])=>[key,h.mode,h.max_body_kb||'inherit',h.body_timeout_ms||'inherit',capabilities.paranoia_levels ? h.paranoia_level||'inherit':'not supported',actions(button('Edit',()=>{ $('host-key').value=key;$('host-mode').value=h.mode;$('host-body').value=h.max_body_kb||0;$('host-timeout').value=h.body_timeout_ms||0;$('host-pl').value=h.paranoia_level||0;$('host-key').focus();}),button('Remove',async()=>{if(!confirm(`Remove override for ${key}?`))return;const c=clone();delete c.hosts[key];await save(c);} ))]));
 table('exception-list',['Rule','Host','Path / method / argument','Reason','Expires','Actions'],config.exceptions.map(ex=>[ex.rule_id,ex.host,`${ex.path||'any path'} · ${ex.method||'any method'} · ${ex.argument||'whole rule'}`,ex.reason,`${new Date(ex.expires_at).toLocaleString()}${new Date(ex.expires_at)<=new Date() ? ' (expired)':''}`,actions(button('Edit',()=>draft(ex,ex.id),!capabilities.rule_exclusions),button('Remove',async()=>{if(!confirm(`Remove exception ${ex.id}?`))return;const c=clone();c.exceptions=c.exceptions.filter(e=>e.id!==ex.id);await save(c);} ))]));
}
async function load() {const state=await api('api/state');config=state.config;capabilities=state.capabilities;fillSettings();renderModeImpact();renderHealth(state);renderOverview(await api('api/summary'));renderPolicies();await refreshChanges();await refreshEvents();notice(state.load_error||'Saved configuration loaded. Fresh installs are off by default.',Boolean(state.load_error));}
async function save(c) {
 if (busy) throw new Error('A save is already running.');busy=true;
 document.querySelectorAll('button[type="submit"]').forEach(b=>b.disabled=true);
 try {config=await api('api/config',{method:'PUT',body:JSON.stringify(c)});const state=await api('api/state');capabilities=state.capabilities;setCapabilities(val('engine'));renderPolicies();renderHealth(state);renderModeImpact();renderOverview(await api('api/summary'));await refreshChanges();notice(`Configuration revision ${config.revision} saved. Adoption pending: Zoraxy refreshes its policy cache on traffic within about 1 second; this page cannot confirm the core's adoption. Retention changes need a plugin restart.`);}
 finally {busy=false;document.querySelectorAll('button[type="submit"]').forEach(b=>b.disabled=false);}
}
function onForm(id,fn) {$(id).addEventListener('submit',e=>{e.preventDefault();Promise.resolve().then(fn).catch(err=>notice(err.message,true));});}
$('settings-form').addEventListener('input',()=>dirty=true);$('engine').addEventListener('change',()=>setCapabilities(val('engine')));
const MODE_IMPACT = {off: 'Off: requests are not inspected at all; nothing is recorded. Only hosts with their own override stay protected.',
 report: 'Report only: every request is inspected and attacks are recorded in Events and the overview, but nothing is blocked. Use this first to learn what the rules would hit on your sites.',
 block: 'Block: detected attacks get a 403 before Zoraxy routes them. Review Events and add scoped exceptions for false positives.'};
let lastSummary = null;
const RANK = {off: 0, report: 1, block: 2};
function renderModeImpact() {
 const m = val('mode'), saved = config && config.mode; let t = MODE_IMPACT[m] || '';
 if (saved && saved !== m) {
  t = `Changing ${saved} → ${m}. ` + t;
  if (lastSummary && RANK[m] < RANK[saved]) {
   const h = lastSummary.history.h24, hosts = lastSummary.top_hosts.length, n = h.blocked + h.would_block;
   if (n) t += ` In the last 24 hours ${fmt(n)} attack${n === 1 ? '' : 's'} on ${hosts} host${hosts === 1 ? '' : 's'} would ${m === 'off' ? 'have reached your sites unseen' : 'have reached your sites (recorded only)'}. Hosts with their own override keep their mode; every change can be restored from the history below.`;
  }
 }
 $('mode-impact').textContent = t; $('mode-impact').classList.toggle('loss', !!(saved && RANK[m] < RANK[saved]));
}
$('mode').addEventListener('change', renderModeImpact);
async function refreshChanges() {
const list = await api('api/changes');
 if (!list.length) { $('changes').textContent = 'No saved revisions yet. The history starts with the next save; the configuration loaded now predates it.'; return; }
 const rows = list.map(e => {
  const changes = document.createElement('ul'); changes.className = 'changes';
  if (!e.changes || !e.changes.length) { const li = document.createElement('li'); li.textContent = 'no field changed'; changes.append(li); }
  for (const c of e.changes || []) { const li = document.createElement('li'); const code = document.createElement('code'); code.textContent = c.field; li.append(code, ' ', c.to === 'changed' && c.from === '' ? 'changed' : c.from === '' ? `set to ${c.to || '(empty)'}` : c.to === '' ? `removed (was ${c.from})` : `${c.from} → ${c.to}`); changes.append(li); }
  const act = e.revision === config.revision ? 'current' : button('Restore', async () => { if (!confirm(`Restore revision ${e.revision}? The current settings stay in the history.`)) return; try { await api('api/changes/revert', {method: 'POST', body: JSON.stringify({revision: e.revision})}); await load(); notice(`Revision ${e.revision} restored as revision ${config.revision}.`); } catch (err) { notice(err.message, true); } });
  return [new Date(e.time).toLocaleString(), String(e.revision), changes, act];
 });
 table('changes', ['When', 'Revision', 'Changes', ''], rows);
}

onForm('settings-form',async()=>{
 const c=clone();c.engine=val('engine');c.mode=val('mode');c.max_body_kb=num('max-body');c.body_timeout_ms=num('body-timeout');c.max_concurrent=num('max-concurrent');
 if(c.engine==='coraza') c.coraza={paranoia_level:num('paranoia'),anomaly_threshold:num('threshold')};
 if(c.engine==='crowdsec') c.crowdsec={url:val('appsec-url'),api_key:val('appsec-key'),timeout_ms:num('appsec-timeout')};
 c.events={ring_size:num('ring-size'),max_file_kb:num('max-file'),max_files:num('max-files')};c.gc_target=Number((document.querySelector('input[name="gc-target"]:checked')||{value:config.gc_target}).value);await save(c);$('appsec-key').value='';dirty=false;
});
$('reload').addEventListener('click',()=>{if(dirty&&!confirm('Discard unsaved global settings?'))return;load().catch(e=>notice(e.message,true));});
onForm('failure-form',async()=>{const c=clone();c.fail_closed=$('fail-closed').checked;c.invert_failure_hosts=val('failure-hosts').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);await save(c);});
onForm('host-form',async()=>{const c=clone();const key=val('host-key').trim();c.hosts[key]={mode:val('host-mode'),max_body_kb:num('host-body'),body_timeout_ms:num('host-timeout'),paranoia_level:capabilities.paranoia_levels?num('host-pl'):0};await save(c);});
function draft(ex,id='') {
 exceptionID=id;tab('exceptions');
 for(const [input,field] of Object.entries({'exception-rule':'rule_id','exception-host':'host','exception-method':'method','exception-path':'path','exception-argument':'argument','exception-reason':'reason'})) $(input).value=ex[field]||'';
 $('exception-expiry').value=localDate(ex.expires_at||Date.now()+7*86400000);$('exception-reason').focus();notice('Draft only: review scope, provide a reason and explicitly approve.');
}
$('exception-cancel').addEventListener('click',()=>{exceptionID='';$('exception-form').reset();});
onForm('exception-form',async()=>{
 const c=clone();const previous=c.exceptions.find(e=>e.id===exceptionID);const now=new Date();
 const ex={id:exceptionID||Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join(''),rule_id:num('exception-rule'),host:val('exception-host').trim(),method:val('exception-method'),path:val('exception-path'),argument:val('exception-argument'),reason:val('exception-reason'),created_at:previous?.created_at||now.toISOString(),expires_at:new Date(val('exception-expiry')).toISOString()};
 if(new Date(ex.expires_at)<=now)throw new Error('Expiry must be in the future.');if(!ex.path||ex.path.includes('*'))throw new Error('Use an exact path for this UI exception.');
 c.exceptions=c.exceptions.filter(e=>e.id!==ex.id);c.exceptions.push(ex);await save(c);exceptionID='';$('exception-form').reset();
});
function query() {const q=new URLSearchParams({limit:'200'});for(const [id,key] of Object.entries({'filter-host':'host','filter-action':'action','filter-rule':'rule_id','filter-ip':'client_ip','filter-text':'text'}))if(val(id))q.set(key,val(id));if(val('filter-since'))q.set('since',new Date(val('filter-since')).toISOString());return q.toString();}
async function suggestions(ev) {const rows=await api(`api/events/${encodeURIComponent(ev.id)}/suggestions`);if(!rows.length){notice('No detection-rule suggestion available for this event.');return;}tab('learning');table('learning-list',['Rule','Host','Method / path','Argument','Review'],rows.map(s=>[s.rule_id,s.host,`${s.method} ${s.path}`,s.argument||'whole rule',button('Review draft',()=>draft(s))]));}
function ago(iso) { const s = Math.max(0, (Date.now() - new Date(iso)) / 1000); const t = document.createElement('time'); t.dateTime = iso; t.title = new Date(iso).toLocaleString(); t.textContent = s < 60 ? `${Math.round(s)} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : new Date(iso).toLocaleString(); return t; }
function hostCell(ev) { const d = document.createElement('div'); d.append(ev.host || ev.route_id || '–'); if (ev.route_id && ev.route_id !== ev.host) { const s = document.createElement('span'); s.className = 'muted'; s.textContent = ev.route_id === '/' ? ' · default site' : ' · route ' + ev.route_id; d.append(s); } return d; }
function ipCell(ip) { const d = document.createElement('div'); d.className = 'ip-cell'; d.append(ip || '–'); if (!ip) return d; const only = document.createElement('button'); only.type = 'button'; only.className = 'linkish'; only.textContent = 'only'; only.title = 'Show only this IP'; only.addEventListener('click', () => { $('filter-ip').value = ip; refreshEvents().catch(e => notice(e.message, true)); }); const who = document.createElement('a'); who.href = 'https://www.whois.com/whois/' + encodeURIComponent(ip); who.target = '_blank'; who.rel = 'noopener'; who.textContent = 'whois'; const block = document.createElement('button'); block.type = 'button'; block.className = 'linkish'; block.textContent = 'block in Zoraxy'; block.title = 'Copies the IP and opens Zoraxy Access Control (blacklist)'; block.addEventListener('click', () => { navigator.clipboard && navigator.clipboard.writeText(ip).catch(() => {}); zoraxyTab('access'); }); d.append(' ', only, ' ', who, ' ', block); return d; }
let openDetailID = '';
function toggleDetail(ev) { openDetailID = openDetailID === ev.id ? '' : ev.id; renderEvents(); }
function insertDetailRow() {
 if (!openDetailID) return;
 const i = eventRows.findIndex(e => e.id === openDetailID); if (i < 0) { openDetailID = ''; return; }
 const tr = $('event-list').querySelector('tbody').rows[i]; const row = document.createElement('tr'); row.className = 'detail-row'; const td = row.insertCell(); td.colSpan = tr.cells.length;
 const pre = document.createElement('pre'); pre.textContent = JSON.stringify(eventRows[i], null, 2); td.append(pre); tr.after(row);
}
function renderEvents() {
 document.querySelectorAll('#chips [data-chip]').forEach(x => x.classList.toggle('active', x.dataset.chip === $('filter-action').value));
 table('event-list',['When','Host / route','Client','Request','Category','Action / blocker','Coverage','Rules','Actions'],eventRows.map(ev=>[ago(ev.time),hostCell(ev),ipCell(ev.client_ip),`${ev.method} ${ev.path}`,ev.category||'–',`${ev.action} · ${ev.action==='blocked'?'WAF':ev.action==='oversize'&&ev.status===413?'WAF body limit':'no enforced WAF block'}`,ev.coverage,(ev.matches||[]).map(m=>m.rule_id).join(', ')||'unavailable',actions(button(openDetailID===ev.id?'Close':'Details',()=>toggleDetail(ev)),button('Suggest exception',()=>suggestions(ev),!capabilities.rule_exclusions||!(ev.matches||[]).length))]));
 insertDetailRow();
 const learning=eventRows.filter(ev=>ev.action==='would_block' && (ev.matches||[]).length);
 table('learning-list',['Host','Path','Detection','Review'],learning.map(ev=>[ev.route_id||ev.host,ev.path,(ev.matches||[]).map(m=>m.rule_id).join(', '),button('Suggest exception',()=>suggestions(ev),!capabilities.rule_exclusions)]));
}
async function refreshEvents() {eventRows=await api('api/events?'+query());$('export').href='api/export?'+query();renderEvents();}
onForm('filter-form',refreshEvents);
document.querySelectorAll('#chips [data-chip]').forEach(b => b.addEventListener('click', () => { $('filter-action').value = b.dataset.chip; document.querySelectorAll('#chips [data-chip]').forEach(x => x.classList.toggle('active', x === b)); refreshEvents().catch(e => notice(e.message, true)); }));
let refreshing=false;
setInterval(async()=>{if(refreshing||busy||!config||!$('live').checked)return;refreshing=true;try{renderHealth(await api('api/state'));if(!$('overview').hidden)renderOverview(await api('api/summary'));if(!$('learning').hidden)return;await refreshEvents();}catch(e){notice(e.message,true);}finally{refreshing=false;}},3000);
load().catch(e=>notice(e.message,true));
