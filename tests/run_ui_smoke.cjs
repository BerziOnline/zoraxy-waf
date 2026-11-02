// Reproducible browser journey against the real binary and a loopback proxy fixture.
// Build first. Install playwright, or point PLAYWRIGHT_MODULE at an existing module.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const { spawn } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
global.profileSmoke = require('./ui_profile_smoke.cjs');
const fixture = spawn('python3', [join(__dirname, 'ui_fixture.py')], {env:process.env, stdio:['ignore','pipe','inherit']});
(async () => {
 let browser;
 try {
  await new Promise((resolve,reject) => {
   const timer=setTimeout(()=>reject(new Error('Fixture startup timeout')),15000);
   fixture.stdout.on('data',data=>{process.stdout.write(data);if(String(data).includes('UI fixture ready')){clearTimeout(timer);resolve();}});
   fixture.once('exit',code=>{clearTimeout(timer);reject(new Error('Fixture exited: '+code));});
  });
  // PLAYWRIGHT_CHANNEL=bundled uses Playwright's own Chromium (dev pool); default: installed Chrome.
  const channel=process.env.PLAYWRIGHT_CHANNEL||'chrome';
  browser=await chromium.launch({headless:true,chromiumSandbox:false,...(channel==='bundled'?{}:{channel})});
  // The journey runs inside a copy of Zoraxy's sandboxed plugin frame, like in production:
  // DOM work goes to the frame, browser-level work (requests, routes, events, viewport) to the page.
  const top=await browser.newPage({viewport:{width:1280,height:900}});
  await top.goto('http://127.0.0.1:18483/zoraxy.html');
  const frame=await (await top.waitForSelector('#pluginContextLoader')).contentFrame();
  const PAGE_ONLY=new Set(['on','once','off','route','unroute','request','setViewportSize','viewportSize','keyboard','mouse','addInitScript','screenshot','waitForEvent','context','close']);
  const page=new Proxy(top,{get(_,k){const src=!PAGE_ONLY.has(k)&&k in frame?frame:top;const v=src[k];return typeof v==='function'?v.bind(src):v;}});
  const journey=vm.runInThisContext(readFileSync(join(__dirname,'ui_smoke.js'),'utf8'));
  console.log(JSON.stringify(await journey(page),null,2));
 } catch (e) { console.error(e);process.exitCode=1; }
 finally {if(browser)await browser.close();fixture.kill('SIGTERM');await new Promise(resolve=>{if(fixture.exitCode!==null)resolve();else fixture.once('exit',resolve);});}
 if (!process.env.WAF_PROFILE_FIXTURE && !process.exitCode) { const child=spawn(process.execPath,[__filename],{env:{...process.env,WAF_PROFILE_FIXTURE:'1'},stdio:'inherit'});process.exitCode=await new Promise(resolve=>child.once('exit',resolve)); }
})();
