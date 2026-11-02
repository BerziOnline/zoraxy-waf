// Screenshots of the plugin UI (light/dark/mobile) with realistic data, via the loopback fixture.
// Usage: PLAYWRIGHT_MODULE=... node tests/ui_shots.cjs <outdir>
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const { spawn } = require('node:child_process');
const { join } = require('node:path');
const out = process.argv[2] || '/tmp/ui-shots';
require('node:fs').mkdirSync(out, { recursive: true });
const fixture = spawn('python3', [join(__dirname, 'ui_fixture.py')], { env: process.env, stdio: ['ignore', 'pipe', 'inherit'] });
const base = 'http://127.0.0.1:18483/plugin.ui/org.zoraxy.waf/';
const attacks = [['/search?q=%27%20OR%201%3D1--', '198.51.100.7'], ['/search?q=%3Cscript%3Ealert(1)%3C/script%3E', '198.51.100.7'], ['/download?f=../../../../etc/passwd', '203.0.113.9'],
 ['/ping?h=127.0.0.1;cat%20/etc/passwd', '203.0.113.9'], ['/search?q=%24%7Bjndi:ldap://x/a%7D', '192.0.2.44'], ['/p?id=1%20UNION%20SELECT%20a,b%20FROM%20u', '198.51.100.7'], ['/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E', '192.0.2.44']];
(async () => {
 let browser;
 try {
  await new Promise((resolve, reject) => { const t = setTimeout(() => reject(new Error('fixture timeout')), 15000); fixture.stdout.on('data', d => { if (String(d).includes('UI fixture ready')) { clearTimeout(t); resolve(); } }); fixture.once('exit', c => reject(new Error('fixture exit ' + c))); });
  const channel = process.env.PLAYWRIGHT_CHANNEL || 'chrome';
  browser = await chromium.launch({ headless: true, chromiumSandbox: false, ...(channel === 'bundled' ? {} : { channel }) });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.goto(base); await page.locator('#notice').waitFor({ state: 'hidden' });
  // Fresh install: activation dialog (desktop + mobile), then learning with one report host and real CRS events.
  await page.screenshot({ path: join(out, 'setup-light.png'), fullPage: false });
  await page.setViewportSize({ width: 390, height: 844 }); await page.locator('details.setup-risk summary').click(); await page.screenshot({ path: join(out, 'setup-mobile.png'), fullPage: false }); await page.setViewportSize({ width: 1280, height: 900 });
  await page.locator('#setup-form button[type="submit"]').click(); await page.locator('.inline-notice').filter({ hasText: 'Learning started' }).waitFor();
  await page.locator('[data-tab="hosts"]').click(); await page.locator('#host-add').click(); await page.locator('#host-key').fill('blog.example'); await page.locator('#host-mode').selectOption('report'); await page.locator('#host-form button[type="submit"]').click(); await page.locator('.inline-notice').filter({ hasText: 'Saved blog.example: Report only, Website.' }).waitFor();
  for (const [host, n] of [['shop.example', 3], ['blog.example', 2], ['api.example', 1]]) for (let i = 0; i < n; i++) for (const [uri, ip] of attacks) {
   await page.request.post('http://127.0.0.1:18482/inspect', { data: { method: 'GET', host, hostname: host, request_uri: uri, proto: 'HTTP/1.1', client_ip: ip, remote_addr: ip + ':4000', route_id: host, protocol_version: 1, header: { 'User-Agent': ['Mozilla/5.0'], Accept: ['text/html'] } } });
  }
  const patchReq = { method: 'PATCH', host: 'api.example', hostname: 'api.example', request_uri: '/api/items/8f3k2m9q1x7d4b6p', proto: 'HTTP/1.1', client_ip: '192.0.2.10', remote_addr: '192.0.2.10:4000', route_id: '', protocol_version: 1, body: Buffer.from('{"done":true}').toString('base64'), header: { 'User-Agent': ['Mozilla/5.0'], 'Content-Type': ['application/json'], Cookie: ['session=x'] } };
  for (let i = 0; i < 41; i++) await page.request.post('http://127.0.0.1:18482/inspect', { data: patchReq });
  await page.locator('[data-tab="overview"]').click(); await page.locator('#hm-today').filter({ hasText: /^[1-9]/ }).waitFor(); await page.waitForTimeout(3500);
  await page.screenshot({ path: join(out, 'overview-light.png'), fullPage: true });
  await page.locator('[data-tab="hosts"]').click(); await page.locator('#host-list').filter({ hasText: 'www.api.example' }).waitFor({ timeout: 15000 }); await page.screenshot({ path: join(out, 'hosts-light.png'), fullPage: true });
  await page.locator('[data-tab="learning"]').click(); await page.locator('#learn-suggest').filter({ hasText: 'PATCH' }).waitFor(); await page.screenshot({ path: join(out, 'learning-light.png'), fullPage: true });
  await page.locator('[data-tab="events"]').click(); await page.waitForTimeout(500); await page.screenshot({ path: join(out, 'events-light.png'), fullPage: true });
  await page.locator('[data-tab="settings"]').click(); await page.screenshot({ path: join(out, 'settings-light.png'), fullPage: true });
  await page.evaluate(() => { localStorage.setItem('theme', 'dark'); location.reload(); }); await page.locator('#hm-today').filter({ hasText: /^[1-9]/ }).waitFor(); await page.waitForTimeout(500);
  await page.screenshot({ path: join(out, 'overview-dark.png'), fullPage: true });
  await page.locator('[data-tab="hosts"]').click(); await page.locator('#host-list').filter({ hasText: 'www.api.example' }).waitFor({ timeout: 15000 }); await page.screenshot({ path: join(out, 'hosts-dark.png'), fullPage: true });
  await page.evaluate(() => localStorage.removeItem('theme'));
  await page.setViewportSize({ width: 390, height: 844 }); await page.reload(); await page.locator('#hm-today').filter({ hasText: /^[1-9]/ }).waitFor(); await page.waitForTimeout(500);
  let overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  await page.screenshot({ path: join(out, 'overview-mobile.png'), fullPage: true });
  for (const t of ['hosts', 'learning']) { await page.locator(`[data-tab="${t}"]`).click(); await page.waitForTimeout(800); overflow = Math.max(overflow, await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)); await page.screenshot({ path: join(out, t + '-mobile.png'), fullPage: true }); }
  fixture.kill('SIGTERM'); await new Promise(r=>fixture.exitCode!==null?r():fixture.once('exit',r));
  const child=spawn(process.execPath,[join(__dirname,'ui_profiles_walkthrough.cjs'),join(out,'profiles')],{env:process.env,stdio:'inherit'});
  const code=await new Promise(r=>child.once('exit',r));if(code)throw new Error('Profile screenshot checks failed: '+code);
  const profileResult=JSON.parse(require('node:fs').readFileSync(join(out,'profiles','profiles.json'),'utf8'));overflow=Math.max(overflow,profileResult.mobile_overflow_px);
  console.log(JSON.stringify({ out, mobile_overflow_px: overflow }));
  if (overflow > 0) process.exitCode = 1;
 } catch (e) { console.error(e); process.exitCode = 1; } finally { if (browser) await browser.close(); fixture.kill('SIGTERM'); }
})();
