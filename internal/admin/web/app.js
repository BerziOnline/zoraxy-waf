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
let config, capabilities, eventRows = [], exceptionID = '', busy = false, dirty = false, setupRequired = false, hostsData = null, findingsHost = '';
const val = id => $(id).value;
const num = id => Number(val(id));
const clone = () => structuredClone(config);
// Feedback appears where the user acted: after the submit button of a form,
// otherwise at the top of the tab the button was in. Only page-level errors
// (loading failed, live refresh failed) use the bar at the top of the page.
// Success messages disappear after a few seconds; errors stay.
let actionCtx = null, noticeTimer = 0;
document.addEventListener('click', e => { const b = e.target.closest('button'); if (b) actionCtx = {button: b, form: b.closest('form'), section: b.closest('section')}; }, true);
document.addEventListener('submit', e => { const b = e.target.querySelector('button[type="submit"]'); actionCtx = {button: b, form: e.target, section: e.target.closest('section')}; }, true);
function notice(message, error = false, act = null, anchor = null) {
 const ctx = actionCtx; actionCtx = null; clearTimeout(noticeTimer);
 document.querySelectorAll('.inline-notice').forEach(n => n.remove()); $('notice').hidden = true;
 const n = el('div', message, 'inline-notice ui ' + (error ? 'negative' : 'positive') + ' message'); n.setAttribute('role', error ? 'alert' : 'status');
 if (act) { n.classList.add('has-action'); n.append(' '); const b = el('button', act.label, 'linkish'); b.type = 'button'; b.addEventListener('click', () => { n.remove(); Promise.resolve().then(act.fn).catch(e => notice(e.message, true)); }); n.append(b); }
 if (anchor && anchor.isConnected && anchor.offsetParent !== null) { anchor.after(n); n.scrollIntoView({block: 'nearest'}); if (!error && !act) noticeTimer = setTimeout(() => n.remove(), 8000); return; }
 const shown = e => e && e.isConnected && e.offsetParent !== null;
 let section = ctx && ctx.section; while (section && !shown(section)) section = section.parentElement && section.parentElement.closest('section');
 if (ctx && shown(ctx.form)) ctx.form.append(n);
 else if (section) { const h = section.querySelector(':scope > h2'); if (h) h.after(n); else section.prepend(n); }
 else { const top = $('notice'); top.hidden = false; top.textContent = message; top.className = 'ui ' + (error ? 'negative' : 'positive') + ' message'; top.setAttribute('role', error ? 'alert' : 'status'); if (!error) noticeTimer = setTimeout(() => { top.hidden = true; }, 6000); return; }
 n.scrollIntoView({block: 'nearest'});
 if (!error && !act) noticeTimer = setTimeout(() => n.remove(), 6000);
}
async function api(path, options = {}) {
 const response = await fetch(path, {credentials: 'same-origin', ...options, headers: {'Content-Type':'application/json','X-CSRF-Token':csrf,'X-WAF-CSRF':csrf, ...options.headers}});
 // A Zoraxy restart or logout invalidates the session of an open page: say so instead of a raw error.
 const stale = 'Your Zoraxy session has changed (Zoraxy restarted or you were logged out). Reload the page and try again.';
 if (response.redirected && /login/.test(response.url) || response.ok && !/json/.test(response.headers.get('Content-Type') || '')) { const e = new Error(stale); e.status = 401; throw e; }
 if (!response.ok) { const text = (await response.text()).trim(); const e = new Error(response.status === 403 && /csrf/i.test(text) ? stale : text || `HTTP ${response.status}`); e.status = response.status; throw e; }
 return response.json();
}
function tab(id) { document.querySelectorAll('.inline-notice.has-action').forEach(n => n.remove()); document.querySelectorAll('.tab').forEach(s => s.hidden = s.id !== id); document.querySelectorAll('[data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === id)); }
document.querySelectorAll('[data-tab]').forEach(b => b.addEventListener('click', () => tab(b.dataset.tab)));
function localDate(date) { const d = new Date(date); return new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0,16); }
function setCapabilities(selected = config.engine) {
 const same = selected === config.engine;
 const supportsPL = same ? capabilities.paranoia_levels : selected === 'coraza';
 const supportsExceptions = same ? capabilities.rule_exclusions : selected === 'coraza';
 $('coraza-settings').hidden = !supportsPL; $('crowdsec-settings').hidden = selected !== 'crowdsec';
 // Host/exception forms edit the active engine, not the unsaved selector.
 $('host-pl-field').hidden = !capabilities.paranoia_levels;
 $('exception-add').hidden = !capabilities.rule_exclusions; if (!capabilities.rule_exclusions) $('exception-editor').hidden = true;
 $('exception-unsupported').hidden = capabilities.rule_exclusions;
 $('paranoia').disabled = !supportsPL; $('threshold').disabled = !supportsPL;
 return supportsExceptions;
}
let sinks = [], alertsDirty = false;
const SINK_TYPE = {text: 'Mattermost / Slack', json: 'Webhook (JSON)'};
// The test goes to the saved receivers, so it waits until nothing is pending;
// after a clean save it becomes the recommended (primary) next step.
const sinkDraft = () => ['sink-url', 'sink-name', 'sink-token'].some(id => val(id).trim());
function renderAlertTest() {
 const saved = config ? (config.alerts.sinks || []).length : 0, pending = alertsDirty || sinkDraft(), ready = saved > 0 && !pending;
 $('alerts-test').disabled = !ready; $('alerts-test').classList.toggle('primary', ready); $('alerts-save').classList.toggle('primary', !ready);
 $('alerts-test-note').textContent = !saved ? 'Save a receiver to send a test.' : pending ? 'Save first: the test goes to the saved receivers.' : '';
}
function setAlertsDirty(v) { alertsDirty = v; renderAlertTest(); }
function renderSinks() {
 table('sinks', ['Name', 'Type', 'URL', 'Token', ''], sinks.map((k, i) => [k.name || k.id, SINK_TYPE[k.format] || k.format, k.url, k.token ? 'set' : '–', button('Remove', () => { sinks.splice(i, 1); renderSinks(); setAlertsDirty(true); })]), 'No receiver yet.');
}
function fillAlerts() {
 const a = config.alerts; sinks = structuredClone(a.sinks || []); renderSinks(); setAlertsDirty(false);
 $('alerts-enabled').checked = a.enabled; $('alerts-engine').checked = a.engine_health;
 for (const [id, v] of Object.entries({'alerts-burst': a.burst_count, 'alerts-window': a.burst_window_min, 'alerts-expiry': a.exception_expiry_days, 'alerts-cooldown': a.cooldown_min})) $(id).value = v;
}
function renderAlertStats(st) { if (!st) return; $('alerts-status').textContent = `Delivered ${fmt(st.Sent)} · failed ${fmt(st.Failed)}` + (st.LastSentAt && st.LastSentAt !== '0001-01-01T00:00:00Z' ? ` · last ${new Date(st.LastSentAt).toLocaleString()}` : '') + (st.LastError ? ` · last error: ${st.LastError}` : ''); }
function addSink() {
 const url = val('sink-url').trim(); if (!/^https?:\/\//.test(url)) throw new Error('The webhook URL must start with http:// or https://');
 sinks.push({id: Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join(''), name: val('sink-name').trim() || 'receiver', format: val('sink-format'), url, token: val('sink-token')});
 for (const id of ['sink-name', 'sink-url', 'sink-token']) $(id).value = ''; renderSinks(); setAlertsDirty(true);
}
$('sink-add').addEventListener('click', () => { try { addSink(); } catch (e) { notice(e.message, true); } });
$('alerts-form').addEventListener('input', e => { if (['sink-name', 'sink-url', 'sink-token', 'sink-format'].includes(e.target.id)) renderAlertTest(); else setAlertsDirty(true); });
onForm('alerts-form', async () => {
 if (val('sink-url').trim()) addSink(); // a filled-in receiver counts, no separate click needed
 const alerts = {enabled: $('alerts-enabled').checked, engine_health: $('alerts-engine').checked, burst_count: num('alerts-burst'), burst_window_min: num('alerts-window'), exception_expiry_days: num('alerts-expiry'), cooldown_min: num('alerts-cooldown'), sinks: sinks.map(k => ({id: k.id, name: k.name, format: k.format, url: k.url, token: k.token || ''}))};
 if (alerts.enabled && !alerts.sinks.length) throw new Error('Add at least one receiver before enabling alerts.');
 await save(c => { c.alerts = structuredClone(alerts); }, alerts.enabled ? 'Alerts saved. Send a test to check the receivers.' : 'Saved. Alerts are off.'); fillAlerts();
});
$('alerts-test').addEventListener('click', async () => { try { const st = await api('api/alerts/test', {method: 'POST', body: '{}'}); renderAlertStats(st); notice(`Test alert sent to ${config.alerts.sinks.length} receiver${config.alerts.sinks.length === 1 ? '' : 's'}.`); } catch (e) { notice(e.message, true); } });
function fillAll() { fillSettings(); fillAlerts(); fillFailure(); }
function fillFailure() { $('fail-closed').value = config.fail_closed ? 'closed' : 'open'; renderFailureLabel(); $('failure-hosts').value = config.invert_failure_hosts.join('\n'); }
function fillSettings() {
 const c = config;
 for (const [id, value] of Object.entries({'engine':c.engine,'mode':c.mode,'max-body':c.max_body_kb,'body-timeout':c.body_timeout_ms,'max-concurrent':c.max_concurrent,'paranoia':c.coraza.paranoia_level,'threshold':c.coraza.anomaly_threshold,'appsec-url':c.crowdsec.url,'appsec-timeout':c.crowdsec.timeout_ms,'ring-size':c.events.ring_size,'max-file':c.events.max_file_kb,'max-files':c.events.max_files,'learn-days':c.learning.days})) $(id).value=value;
 $('mode').disabled=setupRequired;
 $('appsec-key').value=''; $('reject-oversize').checked=!!c.reject_oversize; for(const r of document.querySelectorAll('input[name="gc-target"]')) r.checked=Number(r.value)===c.gc_target; dirty=false; setCapabilities();
}
function renderSpeed(state) {
 // The chosen level sets the plugin's own GC target at once. Only GOGC=off on the
 // Zoraxy service is respected (never re-enabled); Zoraxy's own GC is not touched.
 const gc=state.gc_percent, want=config.gc_target, note=$('speed-inactive');
 $('speed-active').textContent=gc<0?'':`Running: level ${gc}.`;
 note.hidden=gc===want;
 note.textContent=gc<0?'Speed has no effect: Zoraxy runs with GOGC=off.':`Saved level ${want} is not running yet (running: ${gc}). Save again or restart the plugin.`;
 $('speed-cores').textContent=`Uses all ${state.cpu_cores} CPU cores.`;
}
function renderHealth(state) {
 if (state.load_error) notice(state.load_error,true);
 renderSpeed(state);
 renderAlertStats(state.alert_stats);
 const e=state.event_stats;$('feed-line').textContent=`Event log: ${fmt(e.written)} written · ${fmt(e.dropped)} dropped · ${fmt(e.write_errors)} write errors.`;
}
const HOUR = {hour:'numeric'}, DAY = {day:'2-digit', month:'2-digit'};
const narrow = () => ($('chart-hours').clientWidth || 600) < 480;
function renderOverview(sum) {
 lastSummary = sum;
 $('dashboard').hidden = setupRequired; if (setupRequired) return;
 const h = sum.history, hero = $('hero');
 // Headline and colour follow what the inspected hosts really do, not the default mode alone.
 const L = sum.learning, n = L.hosts, hs = k => `${k} host${k === 1 ? '' : 's'}`;
 const byMode = !n ? (sum.mode === 'block' ? 'block' : sum.mode === 'learn' ? 'learn' : sum.mode === 'report' ? 'report' : 'off') : '';
 const state = !sum.health.Engine.ok ? 'bad' : n ? (L.blocking === n ? 'ok' : L.open || L.report || L.off ? 'warn' : L.learning ? 'learn' : 'off') : {block: 'ok', learn: 'learn', report: 'warn', off: 'off'}[byMode];
 hero.className = 'hero state-' + state;
 $('hero-headline').textContent = state === 'bad' ? 'Engine problem'
  : n && L.blocking === n ? `Blocking attacks on ${n === 1 ? 'the' : 'all ' + n} host${n === 1 ? '' : 's'}`
  : n && L.blocking ? `${L.blocking} of ${hs(n)} block attacks`
  : n && L.learning ? 'Learning: nothing is blocked yet'
  : n && L.report ? 'Report only: nothing is blocked'
  : n ? 'Inspection is off'
  : {block: 'Blocking attacks', learn: 'Learning: nothing is blocked yet', report: 'Report only: nothing is blocked', off: 'Inspection is off'}[byMode];
 const parts = [];
 if (state === 'bad') parts.push(sum.health.Engine.detail);
 const mix = [[L.blocking, 'blocking'], [L.learning, 'learning'], [L.report, 'report only'], [L.off, 'off']].filter(x => x[0]);
 if (mix.length > 1) parts.push(mix.map(([k, t]) => `${k} ${t}`).join(' · '));
 if (L.next_host) parts.push(`${L.next_host} can block from ${when(L.next_at)} (in ${left(Date.parse(L.next_at) - Date.now())})${L.next_open ? ', once its open findings are resolved' : ''}`);
 const act = $('hero-action'); act.hidden = !L.open;
 if (!act.hidden) act.textContent = `Review ${L.open} open finding${L.open === 1 ? '' : 's'}`;
 $('hero-sub').textContent = parts.join(' · ');
 const hourly = h.hours.map(p => p.blocked + p.would_block); $('hero-spark').hidden = hourly.filter(Boolean).length < 2; spark($('hero-spark'), hourly, '#ffffff');
 const attacks = c => c.blocked + c.would_block;
 $('hm-today').textContent = fmt(attacks(h.today));
 const days = Math.min(h.days_known, 7);
 $('hm-today-note').textContent = days ? `Ø ${((attacks(h.d7) - attacks(h.today)) / days).toFixed(1)} per day over ${days} day${days > 1 ? 's' : ''}` : '';
 $('hm-blocked').textContent = fmt(h.h24.blocked);
 $('hm-recorded').textContent = fmt(h.h24.would_block);
 $('hm-p95').textContent = sum.stats.LatencyP95MS ? `Inspection time p95: ${sum.stats.LatencyP95MS.toFixed(2)} ms (last 1,024 requests)` : '';
 // Status checklist: each item that needs you names the action and opens its tab.
 const list = $('protection-list'); list.replaceChildren();
 for (const it of sum.protection.items) {
  const li = document.createElement('li'); li.className = it.ok ? 'ok' : it.info ? 'info' : 'missing'; li.append(it.label);
  if (!it.ok && it.action) { const b = document.createElement('button'); b.type = 'button'; b.className = 'linkish'; b.textContent = it.action; b.addEventListener('click', () => { tab(it.tab); if (it.tab === 'learning' || it.tab === 'hosts') refreshHosts().then(() => { renderHosts(); renderLearning(); }).catch(e => notice(e.message, true)); }); li.append(' ', b); }
  if (!it.ok && it.hint) li.append(el('span', it.hint, 'hint'));
  list.append(li);
 }
 const series = [{name: 'blocked', color: '#3B6FF5'}, {name: 'not blocked', color: '#FBBF0F'}, {name: 'errors', color: '#E02424'}];
 const vals = c => [c.blocked, c.would_block, c.error + c.oversize];
 const n24 = bars($('chart-hours'), h.hours.map(p => ({label: new Date(p.time).toLocaleTimeString([], HOUR), values: vals(p)})), series, {every: narrow() ? 6 : 4, label: 'Attacks per hour, last 24 hours'});
 $('hours-sub').textContent = `Last 24 hours · ${fmt(h.h24.blocked + h.h24.would_block)} attacks · ${fmt(h.h24.allowed)} clean requests`;
 const n30 = bars($('chart-days'), h.days.map(p => ({label: new Date(p.time).toLocaleDateString([], DAY), values: vals(p)})), series, {every: narrow() ? 7 : 5, label: 'Attacks per day, last 30 days'});
 $('days-sub').textContent = h.since ? `Last 30 days · ${fmt(h.days.reduce((a, p) => a + p.blocked + p.would_block, 0))} attacks` : 'Last 30 days';
 $('cat-sub').textContent = sum.window.events ? `Latest ${fmt(sum.window.events)} events` : '';
 donut($('chart-categories'), sum.categories.map(c => ({label: c.key, value: c.count})), {label: 'Attack types', empty: 'No attacks yet'});
 ranking($('top-hosts'), sum.top_hosts, {total: sum.window.events, empty: 'No attacks yet'});
 ranking($('top-rules'), sum.top_rules.map(r => ({key: r.key, label: r.label, count: r.count})), {total: sum.window.events, empty: 'No rule fired yet'});
 ranking($('top-ips'), sum.top_ips, {total: sum.window.events, action: r => { const b = document.createElement('button'); b.type = 'button'; b.className = 'linkish rank-action'; b.textContent = 'events'; b.title = 'Show the events of this IP'; b.addEventListener('click', () => { clearFilters(); $('filter-ip').value = r.key; tab('events'); refreshEvents(true).catch(e => notice(e.message, true)); }); return b; }, empty: 'No attacks yet'});
 const st = sum.stats;
 donut($('chart-decisions'), [{label: 'allowed', value: st.Allowed, color: '#21ba45'}, {label: 'blocked', value: st.Blocked, color: '#3B6FF5'}, {label: 'not blocked', value: st.WouldBlock, color: '#FBBF0F'}, {label: 'errors', value: st.Errors, color: '#E02424'}, {label: 'body too large', value: st.Oversize, color: '#8B5CF6'}], {label: 'Decisions since start'});
 $('decisions-sub').textContent = `Since the plugin started: ${fmt(st.Inspected)} inspected · ${fmt(st.Saturated)} waited for a free slot · ${fmt(st.Skipped)} skipped`;
}
function button(label, fn, disabled = false, cls = '') {const b=document.createElement('button');b.type='button';b.className='ui small button'+(cls?' '+cls:'');b.textContent=label;b.disabled=disabled;b.addEventListener('click',()=>Promise.resolve().then(fn).catch(e=>notice(e.message,true)));return b;}
function table(id,headers,rows,empty='No entries') {
 const t=document.createElement('table');t.className='ui compact celled table labeled';const head=t.createTHead().insertRow();headers.forEach(h=>{const th=document.createElement('th');th.textContent=h;head.append(th);});const body=t.createTBody();
 rows.forEach(row=>{const tr=body.insertRow();row.forEach((value,i)=>{const td=tr.insertCell();if(headers[i])td.dataset.label=headers[i];if(value instanceof Node) td.append(value);else td.textContent=String(value??'');});});
 if (!rows.length){const td=body.insertRow().insertCell();td.colSpan=headers.length;td.textContent=empty;}$(id).replaceChildren(t);
}
function actions(...nodes) {const d=document.createElement('div');d.className='row-actions';d.append(...nodes);return d;}
function renderPolicies() {
 renderHosts(); renderLearning();
 table('exception-list', ['Rule', 'Host', 'Applies to', 'Reason', 'Expires', ''], config.exceptions.map(ex => {
  const expired = new Date(ex.expires_at) <= new Date();
  return [String(ex.rule_id), ex.host, `${ex.method || 'any method'} ${ex.path || 'any path'} · ${ex.argument ? 'parameter ' + ex.argument : 'whole request'}`, stack(ex.reason, ex.source ? el('span', ex.source.replace('profile:', ''), 'profile-label') : null), el('span', new Date(ex.expires_at).toLocaleDateString() + (expired ? ' (expired)' : ''), expired ? 'warn-text' : ''),
   actions(button('Edit', () => draft(ex, ex.id), !capabilities.rule_exclusions), button('Remove', async () => { if (!await ask(`Remove the exception for rule ${ex.rule_id} on ${ex.host}? The rule then checks ${ex.path} again.`)) return; await save(c => { c.exceptions = c.exceptions.filter(e => e.id !== ex.id); }, `Exception for rule ${ex.rule_id} removed.`); }, false, 'basic red'))];
 }), 'No exceptions. Add them from a finding on the Learning tab or from an event.');
}
async function load() {const state=await api('api/state');config=state.config;capabilities=state.capabilities;setupRequired=state.setup_required;renderSetup();fillAll();renderModeImpact();renderHealth(state);renderOverview(await api('api/summary'));await refreshHosts();renderPolicies();await refreshChanges();await refreshEvents();$('notice').hidden=true;if(state.load_error||state.learning_error)notice(state.load_error||state.learning_error,true);}
// Reload the saved configuration without touching what is typed in the forms.
async function refreshConfig() {const state=await api('api/state');config=state.config;capabilities=state.capabilities;setupRequired=state.setup_required;}
// save applies a change to the saved configuration. Each form changes only
// its own fields, so when the configuration changed meanwhile (an automatic
// switch to blocking, another tab), the change is applied once more on top
// of the newest revision instead of failing.
async function save(mutate, message) {
 if (busy) throw new Error('A save is already running.');busy=true;
 document.querySelectorAll('button[type="submit"]').forEach(b=>b.disabled=true);
 const put=async()=>{const c=clone();await mutate(c);const retention=JSON.stringify(config.events)!==JSON.stringify(c.events);config=await api('api/config',{method:'PUT',body:JSON.stringify(c)});return retention;};
 try {let retention;try{retention=await put();}catch(e){if(e.status!==409||!/configuration changed/.test(e.message))throw e;await refreshConfig();retention=await put();}
  const done=(message||`Saved (revision ${config.revision}).`)+(retention?' Event storage changes apply after a plugin restart.':'');
  try{const state=await api('api/state');capabilities=state.capabilities;setupRequired=state.setup_required;renderSetup();setCapabilities(val('engine'));await refreshHosts();renderPolicies();renderHealth(state);renderModeImpact();renderOverview(await api('api/summary'));await refreshChanges();}
  catch(e){notice(done+' The page could not refresh: reload it to see the current state.',true);return false;}
  notice(done);return true;}
 finally {busy=false;document.querySelectorAll('button[type="submit"]').forEach(b=>b.disabled=false);}
}
// Zoraxy shows plugins in an iframe sandboxed with only allow-scripts and
// allow-same-origin: the browser drops every form submission before a submit
// event fires. Forms are therefore driven by their submit button and the
// Enter key; the submit event is only stopped (standalone page).
function onForm(id, fn) {
 const form = $(id);
 const run = b => {
  actionCtx = {button: b, form, section: form.closest('section')};
  if (!form.checkValidity()) { // show the first problem, also inside a collapsed section
   const bad = form.querySelector(':invalid:not(fieldset)'); for (let d = bad && bad.closest('details'); d; d = d.parentElement.closest('details')) d.open = true;
   form.reportValidity(); return;
  }
  Promise.resolve().then(fn).catch(err => notice(err.message, true));
 };
 form.addEventListener('click', e => { const b = e.target.closest('button[type="submit"]'); if (!b || !form.contains(b)) return; e.preventDefault(); if (!b.disabled) run(b); });
 form.addEventListener('keydown', e => { const t = e.target; if (e.key !== 'Enter' || e.isComposing || !(t instanceof HTMLInputElement) || ['checkbox', 'radio', 'button', 'submit', 'reset', 'file'].includes(t.type)) return; e.preventDefault(); run(form.querySelector('button[type="submit"]')); });
 form.addEventListener('submit', e => e.preventDefault());
}
// confirm() returns false at once in that sandbox (no allow-modals): ask in the page instead.
function ask(text, ok = 'Confirm', danger = false) {
 return new Promise(resolve => {
  const d = $('ask'), yes = $('ask-ok'), no = $('ask-cancel'), ctx = actionCtx;
  $('ask-text').textContent = text; yes.textContent = ok; yes.className = 'ui button ' + (danger ? 'red' : 'primary');
  const done = v => { yes.onclick = no.onclick = d.oncancel = null; if (d.open) d.close(); actionCtx = ctx; resolve(v); };
  yes.onclick = () => done(true); no.onclick = () => done(false); d.oncancel = e => { e.preventDefault(); done(false); };
  d.showModal(); no.focus();
 });
}
// New windows and downloads are blocked in the sandbox, too; the Zoraxy page
// itself is not sandboxed and same-origin, so links open from there.
function openOutside(url, download = '') {
 let doc = document; try { if (window.top !== window && window.top.document.body) doc = window.top.document; } catch (e) {}
 const a = doc.createElement('a'); a.href = new URL(url, location.href).href; a.rel = 'noopener';
 if (download) a.download = download; else a.target = '_blank';
 a.style.display = 'none'; doc.body.append(a); a.click(); a.remove();
}
async function copyText(text) {
 try { await navigator.clipboard.writeText(text); return true; } catch (e) {}
 const t = el('textarea'); t.value = text; t.setAttribute('readonly', ''); t.style.position = 'fixed'; t.style.opacity = '0'; document.body.append(t); t.select();
 let ok = false; try { ok = document.execCommand('copy'); } catch (e) {} t.remove(); return ok;
}
$('settings-form').addEventListener('input',()=>dirty=true);$('engine').addEventListener('change',()=>setCapabilities(val('engine')));
const MODE_IMPACT = {off: 'Hosts with the default mode are not inspected and nothing is recorded.',
 learn: 'Each host learns for the learning period, then blocks on its own once its open findings are resolved. New hosts learn first, too.',
 report: 'Hosts with the default mode record attacks but never block.',
 block: 'Hosts with the default mode block attacks right away (403), new hosts too, without learning.'};
let lastSummary = null;
const RANK = {off: 0, report: 1, learn: 2, block: 3};
function renderModeImpact() {
 const m = val('mode'), saved = config && config.mode; let t = MODE_IMPACT[m] || '';
 if (setupRequired) { $('mode-impact').textContent = 'Turn protection on from the Overview first.'; $('mode-impact').classList.remove('loss'); return; }
 if (saved && saved !== m) {
  t = `Not saved yet. ${t} Hosts with their own mode keep it.`;
 }
 $('mode-impact').textContent = t; $('mode-impact').classList.toggle('loss', !!(saved && RANK[m] < RANK[saved]));
}
$('mode').addEventListener('change', renderModeImpact);
// History in words: known fields get a sentence, the raw change stays in the tooltip.
const unset = v => v === undefined || v === '' || v === 'undefined' || v === 'null';
const modeName = v => MODE_LABEL[String(v).replace(/"/g, '')] || (String(v) === 'inherit' || String(v) === '"inherit"' ? 'default mode' : String(v));
function describe(c) {
 const f = c.field, from = c.from, to = c.to; let m;
 if (['learning.activated_at', 'revision', 'schema_version', 'hosts', 'alerts'].includes(f)) return '';
 if (f === 'mode') return `Default mode: ${modeName(from)} → ${modeName(to)}`;
 if (f === 'learning.days') return `Learning period: ${from} → ${to} days`;
 if (f === 'gc_target') return `Speed level: ${from} → ${to}`;
 if (f === 'fail_closed') return `When inspection fails: ${to === 'true' ? 'reject (503)' : 'let the request through'}`;
 if (f === 'invert_failure_hosts') return 'Failure handling per host changed';
 if (f === 'alerts.enabled') return to === 'true' ? 'Alerts turned on' : 'Alerts turned off';
 if (f === 'alerts.sinks') return 'Alert receivers changed';
 if (f.startsWith('alerts.')) return 'Alert thresholds changed';
 if (f.startsWith('exceptions')) return 'Exceptions changed';
 if ((m = /^hosts\.(.+)\.(mode|methods|max_body_kb|body_timeout_ms|paranoia_level)$/.exec(f))) {
  const host = m[1];
  if (unset(to)) return m[2] === 'mode' ? `${host}: own settings removed` : '';
  if (m[2] === 'mode') return String(to).replace(/"/g, '') === 'inherit' ? `${host}: follows the default mode` : `${host}: mode ${modeName(to)}`;
  if (m[2] === 'methods') { const list = String(to).replace(/[\[\]"]/g, '').split(/,\s*/).filter(Boolean); return `${host}: methods ${hostsData && same(list, hostsData.app_methods) ? 'App / API' : 'Website + ' + list.join(', ')}`; }
  return `${host}: ${m[2] === 'max_body_kb' ? 'body limit' : m[2] === 'body_timeout_ms' ? 'timeout' : 'paranoia level'} ${to}`;
 }
 return `${f}: ${unset(from) ? 'not set' : from} → ${unset(to) ? 'not set' : to}`.slice(0, 120);
}
async function refreshChanges() {
 const list = await api('api/changes');
 if (!list.length) { $('changes').textContent = 'No changes saved yet.'; return; }
 const rows = list.map(e => {
  const changes = document.createElement('ul'); changes.className = 'changes';
  if (e.note) changes.append(el('li', e.note, 'note'));
  for (const c of e.changes || []) { const t = describe(c); if (!t || [...changes.children].some(li => li.textContent === t)) continue; const li = el('li', t); li.title = `${c.field}: ${c.from || 'not set'} → ${c.to || 'not set'}`; changes.append(li); }
  if (!changes.children.length) changes.append(el('li', 'no visible change', 'muted'));
  const act = e.revision === config.revision ? 'current' : button('Restore', async () => {
   // Restoring undoes every revision after this one: list those changes.
   const undo = []; for (const x of list) if (x.revision > e.revision) for (const c of x.changes || []) { const t = describe(c); if (t && !undo.includes(t)) undo.push(t); }
   const lines = undo.slice(0, 10).map(t => '• ' + t).join('\n') + (undo.length > 10 ? `\n• and ${undo.length - 10} more` : '');
   if (!await ask(`Go back to revision ${e.revision}? This undoes the later changes:\n${lines || '• no visible change'}\n\nUnsaved edits on this page are lost. The current state stays in the history.`, 'Restore')) return;
   await api('api/changes/revert', {method: 'POST', body: JSON.stringify({revision: e.revision})}); await load();
   notice(`Settings from revision ${e.revision} restored (now revision ${config.revision}).`, false, null, $('history-title'));
  });
  return [new Date(e.time).toLocaleString([], {day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'}), String(e.revision), changes, act];
 });
 table('changes', ['When', 'Revision', 'Change', ''], rows);
}

onForm('settings-form',async()=>{
 await save(c=>{c.engine=val('engine');c.mode=val('mode');c.max_body_kb=num('max-body');c.body_timeout_ms=num('body-timeout');c.max_concurrent=num('max-concurrent');c.reject_oversize=$('reject-oversize').checked;
 if(c.engine==='coraza') c.coraza={paranoia_level:num('paranoia'),anomaly_threshold:num('threshold')};
 if(c.engine==='crowdsec') c.crowdsec={url:val('appsec-url'),api_key:val('appsec-key'),timeout_ms:num('appsec-timeout')};
 c.events={ring_size:num('ring-size'),max_file_kb:num('max-file'),max_files:num('max-files')};c.learning={...c.learning,days:num('learn-days')};c.gc_target=Number((document.querySelector('input[name="gc-target"]:checked')||{value:config.gc_target}).value);});$('appsec-key').value='';dirty=false;
});
$('reload').addEventListener('click',async()=>{if(dirty&&!await ask('Discard your unsaved changes in Settings?','Discard'))return;fillSettings();renderModeImpact();});
function renderFailureLabel() { $('failure-hosts-label').textContent = val('fail-closed') === 'closed' ? 'Let the request through instead for these hosts (one per line)' : 'Reject instead for these hosts (one per line)'; }
$('fail-closed').addEventListener('change', renderFailureLabel);
onForm('failure-form',()=>save(c=>{c.fail_closed=val('fail-closed')==='closed';c.invert_failure_hosts=val('failure-hosts').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);}));
// ---- host editor ----
const HOST_IMPACT = {inherit: () => `Follows the default mode (${MODE_LABEL[config.mode] || config.mode}).`, off: h => `Requests to ${h} are not inspected.`, learn: h => `${h} learns first and blocks on its own once its open findings are resolved.`, report: h => `${h} records attacks but never blocks.`, block: h => `${h} blocks attacks right away, including mistakes of the rules.`};
function renderHostImpact() { const h = val('host-key').trim() || 'This host'; $('host-impact').textContent = (HOST_IMPACT[val('host-mode')] || (() => ''))(h); }
$('host-mode').addEventListener('change', renderHostImpact); $('host-key').addEventListener('input', renderHostImpact);
function closeHostEditor() { $('host-editor').hidden = true; $('host-add').hidden = false; $('host-key').readOnly = false; placeHostEditor(); }
$('host-cancel').addEventListener('click', closeHostEditor);
$('host-add').addEventListener('click', () => fillHostForm('', null));
onForm('host-form',()=>{const key=val('host-key').trim().toLowerCase();const h={mode:val('host-mode'),max_body_kb:num('host-body'),body_timeout_ms:num('host-timeout'),paranoia_level:capabilities.paranoia_levels?num('host-pl'):0};const m=formMethods();if(m.length)h.methods=m;
 return save(c=>{c.hosts[key]={...c.hosts[key],...h,methods:m};},`Saved ${key}: ${h.mode==='inherit'?'default mode':MODE_LABEL[h.mode]}, ${methodsLabel(m)}.`).then(()=>{$('host-form-title').textContent=`Settings for ${key}`;$('host-key').readOnly=true;$('host-cancel').textContent='Close';});});
$('host-methods').addEventListener('change',()=>{$('host-methods-custom-field').hidden=val('host-methods')!=='custom';});
// ---- exception editor ----
let draftFinding = null, draftRules = []; // finding {host, key}; rules when several flag the request
function draft(ex, id = '', rules = [], evidence = '', finding = null) {
 exceptionID = id; draftFinding = finding; draftRules = rules.length >= 2 ? rules : []; tab('exceptions');
 $('exception-editor').hidden = false; $('exception-add').hidden = true; $('exception-back').hidden = !finding;
 for (const [input, field] of Object.entries({'exception-rule': 'rule_id', 'exception-host': 'host', 'exception-method': 'method', 'exception-path': 'path', 'exception-argument': 'argument', 'exception-reason': 'reason'})) $(input).value = ex[field] || '';
 // Several rules: one checkbox each, all ticked; each exception keeps its rule's parameter.
 const multi = draftRules.length > 0, list = $('exception-rule-list'); list.replaceChildren();
 $('exception-rules').hidden = !multi; $('exception-rule-field').hidden = multi; $('exception-argument-field').hidden = multi; $('exception-rule').required = !multi;
 const allWhole = draftRules.every(r => !r.argument);
 for (const r of draftRules) { const l = el('label', '', 'rule-check'); const c = document.createElement('input'); c.type = 'checkbox'; c.checked = !!r.argument || allWhole; c.value = r.id; l.append(c, ` ${r.id} ${r.message || ''} · `, el('strong', r.argument ? 'parameter ' + r.argument : 'whole request')); list.append(l); }
 $('exception-title').textContent = id ? `Edit exception for rule ${ex.rule_id}` : multi ? `New exceptions: ${draftRules.length} rules flag this request (not saved yet)` : 'New exception (not saved yet)';
 $('exception-editor').querySelector('button[type="submit"]').textContent = multi ? 'Save exceptions' : 'Save exception';
 $('exception-evidence').hidden = !evidence; $('exception-evidence').textContent = evidence;
 $('exception-expiry').value = localDate(ex.expires_at || Date.now() + 30 * 86400000);
 renderExceptionScope();
 $('exception-editor').scrollIntoView({block: 'nearest'}); $('exception-reason').focus();
}
// One sentence above Save: exactly what stops being checked, and until when.
function renderExceptionScope() {
 const out = $('exception-scope'), exp = new Date(val('exception-expiry')), where = `${val('exception-method').trim().toUpperCase() || 'any method'} ${val('exception-host').trim() || '(host)'}${val('exception-path') || ''}`;
 const until = isNaN(exp) ? '' : ` until ${exp.toLocaleDateString([], {day: 'numeric', month: 'short', year: 'numeric'})}`;
 let groups;
 if (draftRules.length) {
  const picked = new Set([...$('exception-rule-list').querySelectorAll('input:checked')].map(c => Number(c.value))), by = new Map();
  for (const r of draftRules) if (picked.has(Number(r.id))) { const k = r.argument || ''; by.set(k, [...(by.get(k) || []), r.id]); }
  groups = [...by].map(([a, ids]) => `${a ? 'in parameter ' + a : 'on the whole request'}: ${ids.join(', ')}`);
  const kept = draftRules.filter(r => !picked.has(Number(r.id))).map(r => r.id);
  if (kept.length) groups.push(`still checked: ${kept.join(', ')}`);
  if (picked.size === 0) groups = [];
 } else groups = val('exception-rule') ? [`${val('exception-argument').trim() ? 'in parameter ' + val('exception-argument').trim() : 'on the whole request'}: ${val('exception-rule')}`] : [];
 out.textContent = groups.length ? `Saving stops these rules from checking ${where}${until}. ${groups.map(g => g[0].toUpperCase() + g.slice(1)).join('. ')}.` : 'Tick at least one rule.';
}
$('exception-form').addEventListener('input', renderExceptionScope); $('exception-form').addEventListener('change', renderExceptionScope);
function closeExceptionEditor() { exceptionID = ''; draftFinding = null; draftRules = []; $('exception-form').reset(); $('exception-editor').hidden = true; $('exception-add').hidden = !capabilities.rule_exclusions; }
$('exception-cancel').addEventListener('click', closeExceptionEditor);
$('exception-add').addEventListener('click', () => draft({}));
$('exception-back').addEventListener('click', () => { const f = draftFinding; closeExceptionEditor(); if (f) { findingsHost = f.host; tab('learning'); renderLearning(); } });
const newID = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
onForm('exception-form',async()=>{
 const previous=config.exceptions.find(e=>e.id===exceptionID);const now=new Date();
 const base={...(previous?.source ? {source:previous.source} : {}),host:val('exception-host').trim(),method:val('exception-method'),path:val('exception-path'),reason:val('exception-reason'),created_at:previous?.created_at||now.toISOString(),expires_at:new Date(val('exception-expiry')).toISOString()};
 if(new Date(base.expires_at)<=now)throw new Error('The expiry must be in the future.');if(!base.path||base.path.indexOf('*')!==-1&&base.path.indexOf('*')!==base.path.length-1)throw new Error('Use an exact path, or a path prefix ending in * (for paths with IDs).');
 let list;
 if (draftRules.length) {
  const picked = new Set([...$('exception-rule-list').querySelectorAll('input:checked')].map(c => Number(c.value)));
  if (!picked.size) throw new Error('Tick at least one rule.');
  list = draftRules.filter(r => picked.has(Number(r.id))).map(r => ({...base, id: newID(), rule_id: Number(r.id), argument: r.argument || ''}));
 } else list = [{...base, id: exceptionID || newID(), rule_id: num('exception-rule'), argument: val('exception-argument')}];
 const finding = draftFinding;
 const done = list.length === 1 ? `Exception for rule ${list[0].rule_id} on ${base.host} saved.` : `${list.length} exceptions for ${base.host} ${base.path} saved.`;
 const fresh = await save(c=>{const ids=new Set(list.map(e=>e.id));c.exceptions=c.exceptions.filter(e=>!ids.has(e.id));c.exceptions.push(...list);}, done);
 closeExceptionEditor();
 // Saved, but the page could not reload: say so where it stays visible, and claim nothing about the finding.
 if (!fresh) { notice(`${done} The page could not refresh: reload it to see the current state${finding ? ' of the finding' : ''}.`, true, null, document.querySelector('#exceptions > h2')); return; }
 if (!finding) { notice(done, false, null, document.querySelector('#exceptions > h2')); return; }
 // State of the finding as the plugin reports it now, not as the tick boxes suggest.
 const f = ((hostsData.hosts.find(r => r.host === finding.host) || {findings: []}).findings).find(x => x.key === finding.key);
 const still = f ? f.rules.filter(x => !f.resolved_rules.includes(x.id)).map(x => x.id) : [];
 findingsHost = finding.host; $('findings-all').checked = !!f && f.status !== 'open'; tab('learning'); renderLearning();
 notice(!f || f.status === 'resolved' || !still.length ? `${done} The finding on ${finding.host} is resolved.` : `${done} The finding stays open: ${still.join(', ')} still flag${still.length === 1 ? 's' : ''} it.`, false, null, $('learn-intro'));
});
// Filters apply on "Apply filters" (or a chip / drill-down); the live refresh keeps the applied set.
let appliedQuery = 'limit=200';
function query() {const q=new URLSearchParams({limit:'200'});for(const [id,key] of Object.entries({'filter-host':'host','filter-action':'action','filter-rule':'rule_id','filter-ip':'client_ip','filter-text':'text'}))if(val(id))q.set(key,val(id));if(val('filter-since'))q.set('since',new Date(val('filter-since')).toISOString());return q.toString();}
function clearFilters() { for (const id of ['filter-host', 'filter-action', 'filter-rule', 'filter-ip', 'filter-text', 'filter-since']) $(id).value = ''; }
async function suggestions(ev) {
 const rows = await api(`api/events/${encodeURIComponent(ev.id)}/suggestions`);
 if (!rows.length) { notice('This event has no rule an exception could cover.'); return; }
 const s0 = rows[0], msg = Object.fromEntries((ev.matches || []).map(m => [m.rule_id, m.message]));
 draft({...s0, reason: ''}, '', rows.map(r => ({id: r.rule_id, message: msg[r.rule_id] || '', argument: r.argument})), `From the event ${ev.method} ${ev.path} on ${ev.host || ev.route_id} (${new Date(ev.time).toLocaleString()}).`);
}
function ago(iso) { const s = Math.max(0, (Date.now() - new Date(iso)) / 1000); const t = document.createElement('time'); t.dateTime = iso; t.title = new Date(iso).toLocaleString(); t.textContent = s < 60 ? `${Math.round(s)} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : new Date(iso).toLocaleString(); return t; }
function hostCell(ev) { const d = document.createElement('div'); d.append(ev.host || ev.route_id || '–'); if (ev.route_id && ev.route_id !== ev.host) { const s = document.createElement('span'); s.className = 'muted'; s.textContent = ev.route_id === '/' ? ' · default site' : ' · route ' + ev.route_id; d.append(s); } return d; }
function ipCell(ip) {
 const d = document.createElement('div'); d.className = 'ip-cell'; d.append(ip || '–'); if (!ip) return d;
 const only = el('button', 'filter', 'linkish'); only.type = 'button'; only.title = 'Show only this IP'; only.addEventListener('click', () => { $('filter-ip').value = ip; refreshEvents(true).catch(e => notice(e.message, true)); });
 const whoURL = 'https://www.whois.com/whois/' + encodeURIComponent(ip), who = document.createElement('a'); who.href = whoURL; who.target = '_blank'; who.rel = 'noopener'; who.textContent = 'whois'; who.addEventListener('click', e => { e.preventDefault(); openOutside(whoURL); });
 const block = el('button', 'block in Zoraxy…', 'linkish'); block.type = 'button'; block.title = 'Copies the IP and opens Zoraxy Access Control, where you add it to the blacklist';
 block.addEventListener('click', async () => { const copied = await copyText(ip); notice(copied ? `${ip} copied. Add it to the blacklist in Access Control.` : `Add ${ip} to the blacklist in Access Control.`); zoraxyTab('access'); });
 d.append(' ', only, ' ', who, ' ', block); return d;
}
const RESULT = {blocked: 'Blocked', would_block: 'Not blocked', error: 'Error', oversize: 'Body too large', allowed: 'Allowed'};
function resultCell(ev) { const t = ev.action === 'would_block' ? `Not blocked (${ev.mode === 'learn' ? 'learning' : 'report only'})` : RESULT[ev.action] || ev.action; return stack(el('div', t, ev.action === 'error' ? 'warn-text' : ''), ev.coverage === 'partial' ? muted('body partly inspected') : null); }
let openDetailID = '';
function toggleDetail(ev) { openDetailID = openDetailID === ev.id ? '' : ev.id; renderEvents(); }
function insertDetailRow() {
 if (!openDetailID) return;
 const i = eventRows.findIndex(e => e.id === openDetailID); if (i < 0) { openDetailID = ''; return; }
 const ev = eventRows[i], tr = $('event-list').querySelector('tbody').rows[i]; const row = document.createElement('tr'); row.className = 'detail-row'; const td = row.insertCell(); td.colSpan = tr.cells.length;
 const ul = el('ul', '', 'changes'); for (const m of ev.matches || []) ul.append(el('li', `${m.rule_id} ${m.message || ''}${(m.targets || []).length ? ' · in ' + m.targets.join(', ') : ''}`));
 if (!ul.children.length) ul.append(el('li', 'No rule details (engine without rule names).', 'muted'));
 const tech = el('details'); tech.append(el('summary', 'Technical details')); const pre = el('pre', JSON.stringify(ev, null, 2)); tech.append(pre);
 td.append(el('div', `Anomaly score ${ev.anomaly_score || 0} · inspected in ${Number(ev.duration_ms || 0).toFixed(1)} ms${ev.coverage === 'partial' ? ' · body partly inspected' : ''}`, 'muted'), ul, tech); tr.after(row);
}
function renderEvents() {
 document.querySelectorAll('#chips [data-chip]').forEach(x => x.classList.toggle('active', x.dataset.chip === new URLSearchParams(appliedQuery).get('action') || (!x.dataset.chip && !new URLSearchParams(appliedQuery).get('action'))));
 table('event-list', ['When', 'Host', 'Client', 'Request', 'Type', 'Result', ''], eventRows.map(ev => [ago(ev.time), hostCell(ev), ipCell(ev.client_ip), `${ev.method} ${ev.path}`, ev.category || '–', resultCell(ev), actions(button(openDetailID === ev.id ? 'Close' : 'Details', () => toggleDetail(ev)), button('Exception…', () => suggestions(ev), !capabilities.rule_exclusions || !(ev.matches || []).length))]), 'No events match the filters.');
 insertDetailRow();
}
async function refreshEvents(apply = false) { if (apply) appliedQuery = query(); eventRows = await api('api/events?' + appliedQuery); $('export').href = 'api/export?' + appliedQuery; renderEvents(); }
onForm('filter-form', () => refreshEvents(true));
$('export').addEventListener('click', e => { e.preventDefault(); openOutside($('export').getAttribute('href'), 'waf-events.jsonl'); });
$('filter-clear').addEventListener('click', () => { clearFilters(); refreshEvents(true).catch(e => notice(e.message, true)); });
document.querySelectorAll('#chips [data-chip]').forEach(b => b.addEventListener('click', () => { $('filter-action').value = b.dataset.chip; refreshEvents(true).catch(e => notice(e.message, true)); }));
let refreshing=false;
let ticks=0;
setInterval(async()=>{if(refreshing||busy||!config||!$('live').checked)return;refreshing=true;try{renderHealth(await api('api/state'));if(!$('overview').hidden)renderOverview(await api('api/summary'));if((!$('hosts').hidden||!$('learning').hidden)&&++ticks%3===0){await refreshHosts();if(!$('learning').hidden)renderLearning();if(!$('hosts').hidden&&$('host-editor').hidden)renderHosts();}if(!$('events').hidden)await refreshEvents();}catch(e){$('notice').hidden=false;$('notice').className='ui negative message';$('notice').textContent='Live refresh failed: '+e.message;}finally{refreshing=false;}},3000);

// ---- activation, hosts, learning ----
function renderSetup() {
 $('setup').hidden = !setupRequired; $('dashboard').hidden = setupRequired;
 if (config) $('setup-days').value = config.learning.days || 7;
}
async function activate(mode) {
 const days = num('setup-days');
 if (mode === 'learn' && !(days >= 1 && days <= 90)) throw new Error('Learning period must be 1–90 days.');
 if (mode === 'block' && !await ask('Block every request the rules flag from now on, without learning? Mistakes of the rules then block real users.', 'Block now', true)) return;
 await api('api/activate', {method: 'POST', body: JSON.stringify({mode, days, accept_risk: mode === 'block' && $('setup-risk').checked})});
 await load();
 notice(mode === 'learn' ? `Learning started: each host learns ${days} days from its first request.` : 'Blocking is on for every host.');
}
onForm('setup-form', () => activate('learn'));
$('setup-risk').addEventListener('change', () => { $('setup-block').disabled = !$('setup-risk').checked; });
$('setup-block').addEventListener('click', () => activate('block').catch(e => notice(e.message, true)));
async function refreshHosts() { [hostsData, profileCatalogue] = await Promise.all([api('api/hosts'), api('api/profiles')]); fillProfileSelect(); }
const same = (a, b) => a.length === b.length && a.every(x => b.includes(x));
function methodsLabel(m) { if (!m || !m.length) return 'Website'; if (hostsData && same(m, hostsData.app_methods)) return 'App / API'; return 'Website + ' + m.join(', '); }
function formMethods() {
 const v = val('host-methods'); if (v === 'website') return []; if (v === 'app') return [...hostsData.app_methods];
 return [...new Set(val('host-methods-custom').toUpperCase().split(/[\s,]+/).filter(Boolean))];
}
function fillHostForm(host, o) {
 o = o || {mode: 'inherit'}; const m = o.methods || [];
 $('host-key').value = host; $('host-key').readOnly = !!host; $('host-mode').value = o.mode || 'inherit'; $('host-body').value = o.max_body_kb || 0; $('host-timeout').value = o.body_timeout_ms || 0; $('host-pl').value = o.paranoia_level || 0;
 $('host-body').placeholder = config.max_body_kb; $('host-timeout').placeholder = config.body_timeout_ms;
 $('host-methods').value = !m.length ? 'website' : same(m, hostsData.app_methods) ? 'app' : 'custom'; $('host-methods-custom').value = m.join(' '); $('host-methods-custom-field').hidden = val('host-methods') !== 'custom';
 $('host-profile').value = ''; $('host-profile-review').replaceChildren();
 $('host-form-title').textContent = host ? `Settings for ${host}` : 'Settings for a host'; $('host-cancel').textContent = 'Cancel';
 document.querySelectorAll('#host-form .inline-notice').forEach(n => n.remove());
 tab('hosts'); $('host-editor').hidden = false; $('host-add').hidden = true; renderHostImpact(); placeHostEditor();
 $('host-editor').scrollIntoView({block: 'nearest'}); (host ? $('host-mode') : $('host-key')).focus();
}
// The editor opens directly under the row it edits; a new host is edited below the list.
function placeHostEditor() {
 const ed = $('host-editor'), key = !ed.hidden && $('host-key').readOnly ? val('host-key') : '';
 document.querySelectorAll('#host-list tr.editing').forEach(r => r.classList.remove('editing'));
 document.querySelectorAll('#host-list tr.editor-row').forEach(r => { if (!r.contains(ed)) r.remove(); });
 const tr = key && [...document.querySelectorAll('#host-list tbody tr')].find(r => r.cells[0] && r.cells[0].textContent === key && !r.classList.contains('editor-row'));
 if (!tr) { if (ed.parentElement.tagName === 'TD') ed.closest('tr').remove(); $('host-add').before(ed); return; }
 tr.classList.add('editing');
 let row = ed.closest('tr.editor-row');
 if (!row) { row = document.createElement('tr'); row.className = 'editor-row'; row.insertCell(); }
 row.cells[0].colSpan = tr.cells.length; row.cells[0].append(ed); tr.after(row);
}
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function stack(...lines) { const d = document.createElement('div'); for (const l of lines) if (l) d.append(l instanceof Node ? l : el('div', l)); return d; }
const MODE_LABEL = {off: 'Off', learn: 'Learn, then block', report: 'Report only', block: 'Block'};
const muted = t => el('div', t, 'muted');
const when = iso => new Date(iso).toLocaleString([], {weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'});
function left(ms) {
 if (ms <= 0) return 'less than a minute';
 const m = Math.ceil(ms / 60000), d = Math.floor(m / 1440), h = Math.floor(m % 1440 / 60);
 return d ? `${d} d ${h} h` : h ? `${h} h ${m % 60} min` : `${m} min`;
}
// Learning progress of one host, from its first request to the moment it
// switches to blocking. The bar and countdown move with the clock; the
// plugin checks every minute, so blocking starts within a minute of the end.
function learnBar(l, state) {
 const wrap = el('div', '', 'learn-wrap'), bar = el('div', '', 'learn-bar ' + state), label = el('div', '', 'muted learn-when');
 bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-valuemin', '0'); bar.setAttribute('aria-valuemax', '100');
 bar.dataset.since = l.since || ''; bar.dataset.until = l.until || ''; bar.dataset.open = l.open || 0;
 bar.append(el('div', '', 'fill')); wrap.append(bar, label); updateLearnBar(wrap); return wrap;
}
function updateLearnBar(wrap) {
 const bar = wrap.firstChild, label = wrap.lastChild, s = Date.parse(bar.dataset.since), u = Date.parse(bar.dataset.until), now = Date.now();
 const p = bar.classList.contains('learning') && u > s ? Math.max(0, Math.min(1, (now - s) / (u - s))) : 1, pct = Math.round(p * 100);
 bar.firstChild.style.width = (p * 100).toFixed(2) + '%'; bar.setAttribute('aria-valuenow', String(pct));
 const open = +bar.dataset.open, cond = open ? ` if the ${open} open finding${open === 1 ? ' is' : 's are'} resolved` : '';
 let t;
 if (bar.classList.contains('learning')) t = now < u ? `blocks ${when(bar.dataset.until)} · in ${left(u - now)}${cond}` : `period over, blocks at the next check${cond}`;
 else if (bar.classList.contains('held')) t = `period over since ${when(bar.dataset.until)} · blocks once the ${open} open finding${open === 1 ? ' is' : 's are'} resolved`;
 else t = 'blocks at the next check (within a minute)';
 label.textContent = t; bar.setAttribute('aria-valuetext', `${pct}% of the learning period · ${t}`);
}
setInterval(() => document.querySelectorAll('.learn-wrap').forEach(updateLearnBar), 5000);
function learnText(r) {
 const l = r.learning; if (!l) return stack(r.mode === 'block' ? 'blocking' : r.mode === 'off' ? 'not inspected' : r.mode === 'report' ? 'records only, never blocks' : '–');
 if (l.state === 'waiting') return stack('waiting for the first request', muted(`then ${l.days} days`));
 const open = l.open ? el('div', `${l.open} open finding${l.open === 1 ? '' : 's'}`, 'warn-text') : null;
 if (l.state === 'learning') return stack(`day ${l.day} of ${l.days} · ${fmt(l.requests)} requests`, learnBar(l, 'learning' + (l.open ? ' open' : '')), open);
 const lost = r.dropped_login ? el('div', `${r.dropped_login} finding(s) with a login not kept (storage limit): restart learning once the others are resolved`, 'warn-text') : null;
 if (l.state === 'held') return stack(`period over · ${fmt(l.requests)} requests`, learnBar(l, 'held'), open, lost, muted('keeps learning until resolved'));
 return stack('ready', learnBar(l, 'ready'));
}
function methodsCell(m) { const label = methodsLabel(m); return stack(label.startsWith('Website +') ? 'Website + extra' : label, muted(!m || !m.length ? 'GET HEAD POST OPTIONS' : '+ ' + m.join(' '))); }
function zoraxyCell(r) {
 const tags = hostsData.routes.tags || [];
 if (r.in_zoraxy) {
  if (r.disabled) return stack('route disabled in Zoraxy');
  if (r.protected) return stack('inspected', muted('tag ' + r.tags.filter(t => tags.includes(t)).join(', ') + (r.route ? ' · alias of ' + r.route + ', own settings' : '')));
  const go = el('button', tags.length ? `add tag ${tags.join(' / ')} in Zoraxy` : 'assign the plugin to a tag in Zoraxy', 'linkish'); go.type = 'button'; go.addEventListener('click', () => zoraxyTab(tags.length ? 'httprp' : 'plugins'));
  return stack(el('div', 'not inspected', 'warn-text'), go);
 }
 if (r.seen_only) return stack('inspected', muted('seen in traffic' + (hostsData.routes.loaded ? ', not a Zoraxy route' : '')));
 return stack('only configured here', muted(hostsData.routes.loaded ? 'not a Zoraxy route, no traffic' : 'Zoraxy route list unavailable'));
}
async function allowMethods(host, methods) {
 await save(c => { const h = c.hosts[host] ? {...c.hosts[host]} : {mode: 'inherit'}; h.methods = [...new Set([...(h.methods || []), ...methods])]; c.hosts[host] = h; }, `${methods.join(', ')} allowed on ${host} only.`);
}
async function setHostMode(host, mode, question) {
 if (question && !await ask(question, MODE_LABEL[mode] || mode, mode === 'block')) return;
 await save(c => { const h = c.hosts[host] ? {...c.hosts[host]} : {}; h.mode = mode; c.hosts[host] = h; }, `${host}: ${MODE_LABEL[mode] || mode}.`);
}
function openFindings(host, open) { findingsHost = host; $('findings-all').checked = !open; tab('learning'); renderLearning(); }
// Rare or risky row actions sit behind "More" so Edit and the open findings stay in front.
function more(...buttons) { const b = buttons.filter(Boolean); if (!b.length) return null; const d = el('details', '', 'more'); d.append(el('summary', 'More')); const box = el('div', '', 'more-menu'); box.append(...b); d.append(box); return d; }
function renderHosts() {
 if (!hostsData || !config) return;
 const ri = hostsData.routes, tags = (ri.tags || []).join(' / ');
 $('routes-note').textContent = !ri.available ? 'Zoraxy has not given this plugin access to its route list yet. Restart Zoraxy once after installing or updating the plugin; until then the list shows hosts from traffic.' : ri.error ? `Zoraxy route list: ${ri.error}${ri.loaded ? ' (showing the last list read)' : ''}.` : ri.loaded ? (tags ? `Only Zoraxy routes with the tag ${tags} are inspected.` : 'No Zoraxy tag sends traffic to this plugin yet: assign the plugin to a tag in Zoraxy → Plugins.') : 'Reading the route list from Zoraxy…';
 const ed = $('host-editor'); if (ed.closest('#host-list')) $('host-add').before(ed); // keep the editor (and what is typed) across the rebuild
 table('host-list', ['Host', 'Zoraxy', 'Mode', 'Methods', 'Service profiles', 'Learning', ''], hostsData.hosts.map(r => {
  const acts = [];
  if (r.open) acts.push(button(`Review ${r.open} finding${r.open === 1 ? '' : 's'}`, () => openFindings(r.host, true), false, 'primary'));
  acts.push(button('Edit', () => fillHostForm(r.host, r.override)));
  const restartable = r.protected && !r.disabled && r.mode !== 'off' && (!r.learning || r.learning.state !== 'waiting');
  const rare = [
   r.findings.length && !r.open ? button(`Findings (${r.findings.length})`, () => openFindings(r.host, false)) : null,
   r.learning ? button('Block now', () => setHostMode(r.host, 'block', `Block attacks on ${r.host} now, before its learning period is over?` + (r.open ? ` Its ${r.open} open finding${r.open === 1 ? '' : 's'} may then block real users.` : '')), false, 'basic red') : null,
   restartable ? button(!r.learning && r.mode === 'report' ? 'Start learning' : 'Restart learning', async () => { if (!await ask(`Let ${r.host} learn for ${config.learning.days} days from its next request, then block on its own?` + (r.findings.length ? ` Its ${r.findings.length} finding${r.findings.length === 1 ? ' is' : 's are'} cleared.` : ''))) return; await api('api/hosts/restart', {method: 'POST', body: JSON.stringify({host: r.host})}); await refreshConfig(); await refreshHosts(); renderPolicies(); await refreshChanges(); notice(`${r.host} learns again from its next request.`); }) : null,
   r.override ? button('Remove own settings', async () => { if (!await ask(`Remove the settings for ${r.host}? It then follows the default mode with website methods.`)) return; await save(c => { delete c.hosts[r.host]; }, `${r.host} follows the default settings again.`); if (val('host-key') === r.host) closeHostEditor(); }, false, 'basic red') : null];
  const m = more(...rare); if (m) acts.push(m);
  return [r.host, zoraxyCell(r), stack(MODE_LABEL[r.mode] || r.mode, r.inherited ? muted('default mode') : muted('set for this host')), methodsCell(r.methods), appliedProfilesCell(r), learnText(r), actions(...acts)];
 }), 'No hosts yet.');
 placeHostEditor();
 const open = hostsData.learning.open; const lt = document.querySelector('[data-tab="learning"]'); lt.textContent = open ? `Learning · ${open} open` : 'Learning'; lt.title = open ? `${open} open finding${open === 1 ? '' : 's'}` : '';
}
const STATUS = {open: 'Open: sent with a login', scanner: 'No login: does not hold the host', dismissed: 'Marked as attack', resolved: 'Resolved'};
function renderLearning() {
 if (!hostsData || !config) return;
 const L = hostsData.learning;
 $('learn-intro').textContent = config.mode === 'learn' || L.learning ? `${L.learning} host${L.learning === 1 ? '' : 's'} learning${L.held ? ` (${L.held} past the period, held by open findings)` : ''} · ${L.blocking} host${L.blocking === 1 ? '' : 's'} blocking.` : 'No host is learning. Set the default mode to Learn, then block (Settings) or restart learning on a host (Hosts).';
 renderProfileSuggestions();
 const sug = $('learn-suggest'); sug.replaceChildren();
 for (const r of hostsData.hosts) for (const sg of r.suggest_methods) {
  if (findingsHost && r.host !== findingsHost) continue;
  const box = el('div', '', 'ui info message suggest'); box.append(el('p', `${r.host} sent ${sg.method} ${fmt(sg.count)} times (${fmt(sg.with_login)} with a login header). Web apps use ${sg.method}; allow it on this host?`));
  box.append(button(`Allow ${sg.method} on ${r.host}`, () => allowMethods(r.host, [sg.method]), false, 'primary'));
  if (hostsData.app_methods.includes(sg.method)) box.append(' ', button('App / API: PUT, PATCH, DELETE', () => allowMethods(r.host, hostsData.app_methods)));
  sug.append(box);
 }
 const all = $('findings-all').checked; const rows = [];
 for (const r of hostsData.hosts) {
  if (findingsHost && r.host !== findingsHost) continue;
  for (const f of r.findings) {
   if (!all && f.status !== 'open') continue;
   const open = f.rules.filter(x => !f.resolved_rules.includes(x.id));
   const args = [...new Set(f.rules.map(x => x.argument || ''))], oneArg = args.length === 1 ? args[0] : null;
   const line = x => el('div', `${f.resolved_rules.includes(x.id) ? '✓ ' : ''}${x.id} ${x.message || ''}${oneArg === null && x.argument ? ' · in ' + x.argument : ''}`, f.resolved_rules.includes(x.id) ? 'muted' : '');
   const rules = stack(oneArg ? muted(`in parameter ${oneArg}`) : null, ...f.rules.slice(0, 3).map(line));
   if (f.rules.length > 3) { const d = el('details', '', 'more-rules'); d.append(el('summary', `${f.rules.length - 3} more rule${f.rules.length === 4 ? '' : 's'}`), ...f.rules.slice(3).map(line)); rules.append(d); }
   const acts = [];
   const exRules = open.filter(x => x.id !== 911100);
   if (open.some(x => x.id === 911100)) acts.push(button(`Allow ${f.method} on ${r.host}`, () => allowMethods(r.host, [f.method]), false, f.status === 'open' ? 'primary' : ''));
   if (exRules.length) acts.push(button(exRules.length === 1 ? `Exception for ${exRules[0].id}…` : `Exceptions for ${exRules.length} rules…`, () => draft({rule_id: exRules[0].id, host: r.host, method: f.method, path: f.exception_path, argument: exRules[0].argument}, '', exRules, `${fmt(f.count)} requests, ${fmt(f.with_login)} with a login header, from ${fmt(f.client_count)} client${f.client_count === 1 ? '' : 's'}. Latest: ${f.example}`, {host: r.host, key: f.key}), !capabilities.rule_exclusions));
   if (f.status !== 'resolved') acts.push(button(f.dismissed ? 'Reopen' : 'Mark as attack', async () => {
    const flip = d => api('api/findings/dismiss', {method: 'POST', body: JSON.stringify({host: r.host, key: f.key, dismissed: d})}).then(refreshHosts).then(() => { renderHosts(); renderLearning(); });
    await flip(!f.dismissed);
    notice(f.dismissed ? 'Finding reopened.' : `${f.method} ${f.path} marked as attack: after the learning period ${r.host} blocks such requests.`, false, f.dismissed ? null : {label: 'Undo', fn: () => flip(false)}, document.querySelector('#learning .findings-filter'));
   }));
   if (!f.dismissed && f.status !== 'resolved') acts[acts.length - 1].title = `No longer holds ${r.host} back; after the learning period such requests are blocked.`;
   const ev = el('button', 'events', 'linkish'); ev.type = 'button'; ev.title = 'Show the events of this request'; ev.addEventListener('click', () => { clearFilters(); $('filter-host').value = r.host; $('filter-text').value = f.path.replace(/\*.*$/, ''); tab('events'); refreshEvents(true).catch(e => notice(e.message, true)); });
   const req = stack(el('div', `${f.method} ${f.path}`), ev); req.title = 'Latest: ' + f.example;
   const st = el('div', STATUS[f.status] || f.status, f.status === 'open' ? 'warn-text' : '');
   rows.push([r.host, req, rules, stack(`${fmt(f.count)} requests`, muted(`${fmt(f.with_login)} with login header · ${fmt(f.client_count)} client${f.client_count === 1 ? '' : 's'}`)), ago(f.last_seen), st, actions(...acts)]);
  }
 }
 table('findings', ['Host', 'Request', 'Rules', 'Seen', 'Last', 'Status', ''], rows, all ? 'No findings.' : 'No open findings.');
 const note = $('findings-host-note'); note.replaceChildren();
 if (findingsHost) { note.append(`Only ${findingsHost} · `); const b = el('button', 'all hosts', 'linkish'); b.type = 'button'; b.addEventListener('click', () => { findingsHost = ''; renderLearning(); }); note.append(b); }
}
$('findings-all').addEventListener('change', renderLearning);
for (const [t, render] of [['learning', renderLearning], ['hosts', renderHosts]]) document.querySelector(`[data-tab="${t}"]`).addEventListener('click', () => { if (t === 'learning') findingsHost = ''; refreshHosts().then(render).catch(e => notice(e.message, true)); });
$('hero-action').addEventListener('click', () => { findingsHost = ''; $('findings-all').checked = false; tab('learning'); refreshHosts().then(() => { renderHosts(); renderLearning(); }).catch(e => notice(e.message, true)); });
$('setup-days').addEventListener('input', () => { const d = num('setup-days'); $('setup-text').textContent = `Each host learns ${d >= 1 ? d : 7} day${d === 1 ? '' : 's'} from its first request and blocks nothing. Then it starts blocking on its own, once its open findings are resolved.`; });

// ---- service profile review (no policy changes until explicit Apply) ----
let profileCatalogue = [], profileReviews = new Map(), profileMessages = new Map();
const profileKey = (host, id) => host + ':' + id;
async function openProfile(host, id, target = 'profile-suggest') {
 const preview = await api('api/profiles/preview?host=' + encodeURIComponent(host) + '&id=' + encodeURIComponent(id));
 profileReviews.set(profileKey(host, id), {preview, target});
 if (target === 'profile-suggest') renderLearning(); else renderManualProfile();
}
// One entry per method + path + field: the rules it stops, where, and why (reason without the profile prefix).
function profileEntries(list) {
 const groups = new Map();
 for (const ex of list) {
  const why = String(ex.reason || '').replace(/^.+? v\d+: /, ''), k = [ex.method, ex.path, ex.argument, why].join('\n');
  if (!groups.has(k)) groups.set(k, {ex, why, rules: []});
  groups.get(k).rules.push(ex.rule_id);
 }
 const ul = el('ul');
 for (const g of groups.values()) {
  const li = el('li');
  li.append(stack(el('strong', `${g.rules.length === 1 ? 'Rule' : 'Rules'} ${g.rules.join(', ')} stop checking ${g.ex.argument ? 'field ' + g.ex.argument : 'this request'}`), el('div', `${g.ex.method} ${g.ex.path}`), muted(g.why)));
  ul.append(li);
 }
 return ul;
}
function profileReviewCard(entry) {
 const pr = entry.preview, p = pr.profile, key = profileKey(pr.host, p.id), box = el('div', '', 'profile-review');
 box.dataset.profile = p.id; box.dataset.host = pr.host;
 box.append(el('h3', `${p.name} profile v${p.version} · ${pr.host}`));
 const short = c => String(c || '').slice(0, 7);
 if (p.crs_plugin) {
  box.append(el('p', `Official CRS package ${p.crs_plugin}, for this host only.`));
  if (pr.plugin_before && pr.plugin_before !== pr.plugin_after) {
   box.append(el('p', `Package update ${short(pr.plugin_before)} → ${short(pr.plugin_after)}`));
   box.append(button('View rule diff', () => openOutside('https://github.com/coreruleset/' + p.crs_plugin + '-plugin/compare/' + pr.plugin_before + '...' + pr.plugin_after)));
  }
 }
 if (pr.removed.length) { box.append(el('h4', 'Removed')); box.append(profileEntries(pr.removed)); }
 if (pr.added.length) { box.append(el('h4', 'Exceptions · expire in 1 year')); box.append(profileEntries(pr.added)); }
 if (!pr.added.length && !p.crs_plugin && !pr.unchanged) box.append(muted('No rule exceptions.'));
 let consent = null;
 const extra = pr.methods_after.filter(m => !pr.methods_before.includes(m));
 if (extra.length && !pr.unchanged) { const l = el('label', '', 'profile-consent'); consent = document.createElement('input'); consent.type = 'checkbox'; consent.checked = !!entry.confirmMethods; l.append(consent, ` Also allow ${extra.join(', ')} on this host`); box.append(l); }
 const apply = button(pr.unchanged ? 'Applied' : 'Apply profile', async () => {
  if (busy) return; busy = true; apply.disabled = true;
  let saved = false;
  try {
   const result = await api('api/profiles/change', {method:'POST', body:JSON.stringify({host:pr.host, id:p.id, action:'apply', confirm_methods:!!consent?.checked, revision:pr.revision})});
   saved = true; config = result.config;
   await refreshHosts();
   const host = hostsData.hosts.find(h => h.host === pr.host);
   const resolved = (host?.findings || []).filter(f => f.status === 'resolved' && result.resolved_keys.includes(f.key)).length;
   profileMessages.set(key, {text:`${p.name} v${p.version} applied. ${resolved} finding${resolved === 1 ? '' : 's'} resolved.`, error:false});
   entry.preview = {...pr, unchanged:true}; renderPolicies(); await refreshChanges();
  } catch (e) {
   profileMessages.set(key, {text:saved ? 'Profile saved. Refresh failed; reload to see the findings.' : e.message, error:true});
   if (saved) entry.preview = {...pr, unchanged:true};
  } finally { busy = false; renderLearning(); renderManualProfile(); }
 }, pr.unchanged || (!!consent && !consent.checked), 'primary');
 if (consent) consent.addEventListener('change', () => { entry.confirmMethods = consent.checked; apply.disabled = !consent.checked || busy; });
 box.append(apply);
 const msg = profileMessages.get(key); if (msg) { const n = el('div', msg.text, 'inline-notice ui message ' + (msg.error ? 'negative' : 'positive')); n.setAttribute('role', msg.error ? 'alert' : 'status'); box.append(n); }
 box.append(button('Close review', () => { profileReviews.delete(key); profileMessages.delete(key); renderLearning(); renderManualProfile(); }));
 return box;
}
function renderProfileSuggestions() {
 const wrap = $('profile-suggest'); wrap.replaceChildren(); const shown = new Set();
 for (const r of hostsData.hosts) {
  if (findingsHost && findingsHost !== r.host) continue;
  for (const p of r.suggested_profiles || []) {
   const key = profileKey(r.host,p.id), line = el('div', '', 'profile-suggestion card'); line.dataset.profile = p.id; line.dataset.host = r.host;
   line.append(el('p', `${r.host} · Looks like ${p.name} (${p.evidence}).`), button('Review profile', () => openProfile(r.host,p.id), false, 'primary'), button('Not ' + p.name, async () => {
    const result = await api('api/profiles/change', {method:'POST',body:JSON.stringify({host:r.host,id:p.id,action:'dismiss',confirm_methods:false,revision:config.revision})});config=result.config;profileReviews.delete(key);await refreshHosts();renderPolicies();await refreshChanges();notice(`${p.name} suggestion dismissed for ${r.host}.`,false,null,$('learn-intro'));
   }));
   const entry = profileReviews.get(key); if (entry?.target === 'profile-suggest') { line.append(profileReviewCard(entry)); shown.add(key); } wrap.append(line);
  }
 }
 for (const [key, entry] of profileReviews) if (entry.target === 'profile-suggest' && !shown.has(key) && (!findingsHost || findingsHost === entry.preview.host)) wrap.append(profileReviewCard(entry));
}
function renderManualProfile() {
 const wrap = $('host-profile-review'); wrap.replaceChildren();
 for (const entry of profileReviews.values()) if (entry.target === 'host-profile-review' && entry.preview.host === val('host-key')) wrap.append(profileReviewCard(entry));
}
function fillProfileSelect() {
 const select = $('host-profile'), keep = select.value; select.replaceChildren(new Option('None', ''));
 for (const p of profileCatalogue) select.add(new Option(`${p.name} v${p.version}${p.crs_plugin ? ' · Coraza' : ''}`,p.id)); select.value = keep;
}
function appliedProfilesCell(r) {
 return stack(...(r.applied_profiles || []).map(p => stack(el('span', `${p.name} v${p.version}${p.modified ? ' · modified' : ''}${p.inactive ? ' · inactive' : ''}`, 'profile-label'),
  p.update_available ? button('Update available · review', () => { tab('learning'); return openProfile(r.host,p.id); }) : p.modified ? button('Restore profile · review', () => { tab('learning'); return openProfile(r.host,p.id); }) : null,
  button('Remove profile', async () => {
   const count = config.exceptions.filter(ex => ex.host === r.host && ex.source?.startsWith('profile:' + p.id + '@')).length;
   if (!await ask(`Remove ${p.name} from ${r.host}? Its ${count} profile exceptions are removed. Method changes stay.`, 'Remove profile', true)) return;
   const result = await api('api/profiles/change', {method:'POST',body:JSON.stringify({host:r.host,id:p.id,action:'remove',confirm_methods:false,revision:config.revision})});config=result.config;profileReviews.delete(profileKey(r.host,p.id));await refreshHosts();renderPolicies();await refreshChanges();notice(`${p.name} removed from ${r.host}. Method changes kept.`,false,null,$('routes-note'));
  },false,'basic')
 )));
}
$('host-profile-review-button').addEventListener('click', () => {
 if (!val('host-profile')) return;
 openProfile(val('host-key').trim().toLowerCase(), val('host-profile'), 'host-profile-review').catch(e => notice(e.message,true));
});

load().catch(e=>notice(e.message,true));
