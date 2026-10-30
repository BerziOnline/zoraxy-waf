// Reproducible browser journey against the real binary and a loopback proxy fixture.
// Build first. Install playwright, or point PLAYWRIGHT_MODULE at an existing module.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const { spawn } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const fixture = spawn('python3', [join(__dirname, 'ui_fixture.py')], {env:process.env, stdio:['ignore','pipe','inherit']});
(async () => {
 let browser;
 try {
  await new Promise((resolve,reject) => {
   const timer=setTimeout(()=>reject(new Error('Fixture startup timeout')),15000);
   fixture.stdout.on('data',data=>{process.stdout.write(data);if(String(data).includes('UI fixture ready')){clearTimeout(timer);resolve();}});
   fixture.once('exit',code=>{clearTimeout(timer);reject(new Error('Fixture exited: '+code));});
  });
  browser=await chromium.launch({headless:true,chromiumSandbox:false,channel:'chrome'});
  const page=await browser.newPage({viewport:{width:1280,height:900}});
  const journey=vm.runInThisContext(readFileSync(join(__dirname,'ui_smoke.js'),'utf8'));
  console.log(JSON.stringify(await journey(page),null,2));
 } catch (e) { console.error(e);process.exitCode=1; }
 finally {if(browser)await browser.close();fixture.kill('SIGTERM');await new Promise(resolve=>{if(fixture.exitCode!==null)resolve();else fixture.once('exit',resolve);});}
})();
