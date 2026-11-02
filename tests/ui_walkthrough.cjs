// Full user walkthrough of the plugin UI against the loopback fixture (real plugin binary).
// Writes numbered screenshots and walkthrough.json (step, action, visible feedback, files) to <outdir>.
// Usage: PLAYWRIGHT_MODULE=... [PLAYWRIGHT_CHANNEL=bundled] node tests/ui_walkthrough.cjs <outdir>
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const { spawn } = require('node:child_process');
const { join } = require('node:path');
const fs = require('node:fs');
const out = process.argv[2] || 'walkthrough';
fs.mkdirSync(out, { recursive: true });
const fixture = spawn('python3', [join(__dirname, 'ui_fixture.py')], { env: process.env, stdio: ['ignore', 'pipe', 'inherit'] });
const base = 'http://127.0.0.1:18483/plugin.ui/org.zoraxy.waf/';
const inspect = 'http://127.0.0.1:18482/inspect';
const attacks = [['/search?q=%27%20OR%201%3D1--', '198.51.100.7'], ['/search?q=%3Cscript%3Ealert(1)%3C/script%3E', '198.51.100.7'], ['/download?f=../../../../etc/passwd', '203.0.113.9'],
 ['/ping?h=127.0.0.1;cat%20/etc/passwd', '203.0.113.9'], ['/search?q=%24%7Bjndi:ldap://x/a%7D', '192.0.2.44'], ['/p?id=1%20UNION%20SELECT%20a,b%20FROM%20u', '198.51.100.7']];
const req = (host, uri, ip, extra = {}) => ({ method: 'GET', host, hostname: host, request_uri: uri, proto: 'HTTP/1.1', client_ip: ip, remote_addr: ip + ':4000', route_id: host, protocol_version: 1, header: { 'User-Agent': ['Mozilla/5.0'], Accept: ['text/html'] }, ...extra });
(async () => {
 let browser; const steps = []; let n = 0;
 try {
  await new Promise((resolve, reject) => { const t = setTimeout(() => reject(new Error('fixture timeout')), 15000); fixture.stdout.on('data', d => { if (String(d).includes('UI fixture ready')) { clearTimeout(t); resolve(); } }); fixture.once('exit', c => reject(new Error('fixture exit ' + c))); });
  const channel = process.env.PLAYWRIGHT_CHANNEL || 'chrome';
  browser = await chromium.launch({ headless: true, chromiumSandbox: false, ...(channel === 'bundled' ? {} : { channel }) });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = []; page.on('pageerror', e => errors.push(e.message)); page.on('console', m => { if (m.type() === 'error') errors.push(m.text() + (m.location()&&m.location().url?' '+m.location().url:'')); }); page.on('requestfailed', r => errors.push('request failed: ' + r.url() + ' ' + (r.failure() ? r.failure().errorText : '')));
  const feedback = async () => (await page.locator('.inline-notice:visible, #notice:visible').allTextContents()).join(' | ');
  async function shot(title, action, opts = {}) {
   n++; const id = String(n).padStart(2, '0'); const files = [];
   const f = `${id}-${opts.name || 'step'}.png`; await page.screenshot({ path: join(out, f), fullPage: !!opts.full }); files.push(f);
   if (opts.mobile) { const vp = page.viewportSize(); await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(400); const m = `${id}-${opts.name || 'step'}-mobile.png`; await page.screenshot({ path: join(out, m), fullPage: true }); files.push(m); await page.setViewportSize(vp); await page.waitForTimeout(300); }
   steps.push({ step: n, title, action, feedback: await feedback(), files });
  }
  const tabTo = async t => { await page.locator(`[data-tab="${t}"]`).click(); await page.waitForTimeout(400); };

  await page.goto(base); await page.locator('#notice').waitFor({ state: 'hidden' });
  await shot('Fresh install: plugin opened for the first time', 'open the plugin page', { name: 'fresh-install', mobile: true, full: true });
  await page.locator('details.setup-risk summary').click();
  await shot('Option to block right away', 'click "Block right away instead"', { name: 'block-now-option' });
  await page.locator('#setup-form button[type="submit"]').click(); await page.locator('.inline-notice, #notice:not([hidden])').first().waitFor();
  await shot('Learning started', 'keep 7 days, click "Start learning (recommended)"', { name: 'learning-started', full: true });

  for (const [host, k] of [['shop.example', 3], ['blog.example', 2], ['api.example', 1]]) for (let i = 0; i < k; i++) for (const [uri, ip] of attacks) await page.request.post(inspect, { data: req(host, uri, ip) });
  const patchReq = req('api.example', '/api/items/8f3k2m9q1x7d4b6p', '192.0.2.10', { method: 'PATCH', route_id: '', body: Buffer.from('{"done":true}').toString('base64'), header: { 'User-Agent': ['Mozilla/5.0'], 'Content-Type': ['application/json'], Cookie: ['session=x'] } });
  for (let i = 0; i < 12; i++) await page.request.post(inspect, { data: patchReq });
  for (let i = 0; i < 40; i++) await page.request.post(inspect, { data: req('shop.example', '/products/' + i, '192.0.2.' + (20 + i % 9)) });
  // A real user's search that trips a rule (logged in): an open finding that needs a decision.
  for (let i = 0; i < 3; i++) await page.request.post(inspect, { data: req('shop.example', '/search?q=%3Cb%3Esale%3C/b%3E%20%3Cscript%3E', '192.0.2.31', { header: { 'User-Agent': ['Mozilla/5.0'], Accept: ['text/html'], Cookie: ['session=abc'] } }) });
  await page.reload(); await page.locator('#hm-today').filter({ hasText: /^[1-9]/ }).waitFor(); await page.waitForTimeout(1500);
  await shot('Overview after one hour of traffic (simulated)', 'reload the page', { name: 'overview', mobile: true, full: true });

  await tabTo('hosts'); await page.locator('#host-list').filter({ hasText: 'www.api.example' }).waitFor({ timeout: 15000 });
  await shot('Hosts tab', 'click tab "Hosts"', { name: 'hosts', mobile: true, full: true });
  const apiRow = page.locator('#host-list tr').filter({ has: page.locator('td', { hasText: /^api\.example$/ }) });
  await apiRow.locator('button', { hasText: 'Edit' }).click(); await page.waitForTimeout(400);
  await shot('Edit a host', 'click "Edit" on api.example', { name: 'host-edit' });
  await page.selectOption('#host-methods', 'app'); await page.locator('#host-form button[type="submit"]').click(); await page.locator('.inline-notice').first().waitFor();
  await shot('Host saved', 'choose "App / API", click "Save host"', { name: 'host-saved' });

  await tabTo('learning'); await page.waitForTimeout(800);
  await shot('Learning tab', 'click tab "Learning"', { name: 'learning', mobile: true, full: true });
  const exc = page.locator('#findings button', { hasText: /^Exceptions? for / }).first();
  if (await exc.count()) { await exc.click(); await page.waitForTimeout(400); await shot('Exception draft from a finding', 'click "Exception for <rule>…" on a finding', { name: 'exception-draft', full: true });
   await page.fill('#exception-reason', 'Search terms with SQL words, checked by me'); await page.locator('#exception-form button[type="submit"]').click(); await page.locator('.inline-notice:visible').first().waitFor({ timeout: 10000 }).catch(() => {});
   await shot('Exception saved', 'enter a reason, click "Save exception"', { name: 'exception-saved', full: true }); }
  await tabTo('learning'); await page.waitForTimeout(400);
  const dismiss = page.locator('#findings button', { hasText: 'Mark as attack' }).first();
  if (await dismiss.count()) { await dismiss.click(); await page.waitForTimeout(800); await shot('Finding marked as attack', 'click "Mark as attack" on a finding', { name: 'finding-dismissed', full: true }); }

  await tabTo('events'); await page.waitForTimeout(600);
  await shot('Live events', 'click tab "Events"', { name: 'events', mobile: true, full: true });
  await page.locator('#event-list button', { hasText: 'Details' }).first().click(); await page.waitForTimeout(300);
  await shot('Event details', 'click "Details" on the newest event', { name: 'event-details' });

  await tabTo('alerts');
  await shot('Alerts tab', 'click tab "Alerts"', { name: 'alerts', full: true });
  await page.fill('#sink-name', 'Mattermost #security'); await page.fill('#sink-url', 'http://127.0.0.1:18483/hook'); await page.locator('#sink-add').click();
  await page.locator('#alerts-enabled').check(); await page.locator('#alerts-form button[type="submit"]').click(); await page.locator('.inline-notice').first().waitFor();
  await shot('Alerts saved', 'add a receiver, tick "enabled", click "Save alerts"', { name: 'alerts-saved', full: true });
  await page.locator('#alerts-test').click(); await page.waitForTimeout(2500);
  await shot('Test alert', 'click "Send test alert"', { name: 'alerts-test' });

  await tabTo('settings');
  await shot('Settings tab', 'click tab "Settings"', { name: 'settings', mobile: true, full: true });
  await page.selectOption('#mode', 'report'); await page.waitForTimeout(200);
  await shot('Changing the default mode (not saved yet)', 'choose "Report only" in Default mode', { name: 'mode-change' });
  await page.selectOption('#mode', 'learn');
  const restore = page.locator('#changes button', { hasText: 'Restore' }).first();
  if (await restore.count()) { await restore.click(); await page.locator('#ask-ok').waitFor(); await shot('Restore asks first', 'click "Restore" in the change history', { name: 'restore-ask' }); await page.locator('#ask-ok').click(); await page.waitForTimeout(800); await shot('Restore an older revision', 'click "Restore" in the change history, confirm', { name: 'restore', full: true }); }

  await tabTo('exceptions');
  await shot('Exceptions tab', 'click tab "Exceptions"', { name: 'exceptions', full: true });

  await page.evaluate(() => { localStorage.setItem('theme', 'dark'); location.reload(); }); await page.locator('#hm-today').filter({ hasText: /^[1-9]/ }).waitFor(); await page.waitForTimeout(600);
  await shot('Overview in dark mode', 'switch Zoraxy to dark mode', { name: 'overview-dark', full: true });
  await tabTo('hosts'); await page.waitForTimeout(600);
  await shot('Hosts in dark mode', 'click tab "Hosts"', { name: 'hosts-dark', full: true });
  await page.evaluate(() => localStorage.removeItem('theme'));

  // Close the page before the fixture stops, or its live refresh reports the closed port as a page error.
  await page.close(); fixture.kill('SIGTERM'); await new Promise(r => fixture.exitCode !== null ? r() : fixture.once('exit', r));
  const child = spawn(process.execPath, [join(__dirname, 'ui_profiles_walkthrough.cjs'), join(out, 'profiles')], {env:process.env,stdio:'inherit'});
  const code = await new Promise(r=>child.once('exit',r)); if(code) throw new Error('Profile walkthrough failed: '+code);
  const profiles = JSON.parse(fs.readFileSync(join(out,'profiles','profiles.json'),'utf8'));
  errors.push(...profiles.page_errors); for(const step of profiles.steps) steps.push({...step,step:steps.length+1,files:step.files.map(f=>'profiles/'+f)});
  fs.writeFileSync(join(out, 'walkthrough.json'), JSON.stringify({ steps, page_errors: errors }, null, 1));
  console.log(JSON.stringify({ out, steps: steps.length, page_errors: errors.length }));
  if (errors.length) { console.error(errors.join('\n')); process.exitCode = 1; }
 } catch (e) { console.error(e); fs.writeFileSync(join(out, 'walkthrough.json'), JSON.stringify({ steps, error: String(e) }, null, 1)); process.exitCode = 1; } finally { if (browser) await browser.close(); fixture.kill('SIGTERM'); }
})();
