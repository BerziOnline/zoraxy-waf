// Profile screenshots and checks inside Zoraxy's actual iframe sandbox.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const { spawn } = require('node:child_process');
const { join } = require('node:path');
const fs = require('node:fs');
const out = process.argv[2]; fs.mkdirSync(out,{recursive:true});
const fixture=spawn('python3',[join(__dirname,'ui_fixture.py')],{env:{...process.env,WAF_PROFILE_FIXTURE:'1'},stdio:['ignore','pipe','inherit']});
(async()=>{let browser;const steps=[],errors=[];let overflow=0;
 try{
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('fixture timeout')),15000);fixture.stdout.on('data',d=>{if(String(d).includes('UI fixture ready')){clearTimeout(timer);resolve();}});fixture.once('exit',c=>reject(new Error('fixture exit '+c)));});
  browser=await chromium.launch({headless:true,chromiumSandbox:false,...(process.env.PLAYWRIGHT_CHANNEL==='bundled'?{}:{channel:process.env.PLAYWRIGHT_CHANNEL||'chrome'})});
  const top=await browser.newPage({viewport:{width:1280,height:1050}});top.on('pageerror',e=>errors.push(e.message));top.on('requestfailed',r=>errors.push('request failed: '+r.url()+' '+(r.failure()?r.failure().errorText:'')));top.on('console',m=>{if(m.type()==='error')errors.push(m.text()+(m.location()&&m.location().url?' '+m.location().url:''));});
  await top.goto('http://127.0.0.1:18483/zoraxy.html');const frame=await (await top.waitForSelector('#pluginContextLoader')).contentFrame();const base='http://127.0.0.1:18483/plugin.ui/org.zoraxy.waf/';
  const shot=async(name,title)=>{const file=name+'.png';await top.screenshot({path:join(out,file),fullPage:true});steps.push({step:steps.length+1,title,action:title,files:[file]});overflow=Math.max(overflow,await frame.evaluate(()=>document.documentElement.scrollWidth-innerWidth));};
  const learning=async()=>{await frame.locator('#notice').waitFor({state:'hidden'});await frame.locator('[data-tab="learning"]').click();await frame.locator('.profile-suggestion[data-profile="mattermost"]').waitFor();};
  const review=async()=>{await frame.locator('.profile-suggestion[data-profile="mattermost"]').getByRole('button',{name:'Review profile',exact:true}).click();await frame.locator('.profile-review').waitFor();};
  await learning();await shot('suggestion-light','Mattermost suggestion from traffic and route evidence');
  await review();await shot('review-light','Review field-scoped exceptions before applying');
  await frame.evaluate(()=>localStorage.setItem('theme','dark'));await frame.goto(base);await learning();await review();await shot('review-dark','Profile review in dark mode');
  await frame.evaluate(()=>localStorage.removeItem('theme'));await frame.goto(base);await learning();await review();await top.setViewportSize({width:390,height:1050});await shot('review-mobile','Profile review on mobile');await top.setViewportSize({width:1280,height:1050});
  await frame.locator('.profile-review input[type="checkbox"]').check();await frame.getByRole('button',{name:'Apply profile',exact:true}).click();await frame.locator('.profile-review .inline-notice').filter({hasText:'2 findings resolved.'}).waitFor();await shot('applied','Apply profile with feedback from refreshed findings');
  await frame.locator('[data-tab="hosts"]').click();await frame.locator('#host-list').filter({hasText:/Mattermost v\d/}).waitFor();await shot('hosts-light','Applied profile shown beside its host');
  await top.setViewportSize({width:390,height:1050});await shot('hosts-mobile','Applied host profile on mobile');await top.setViewportSize({width:1280,height:1050});
  await frame.locator('[data-tab="exceptions"]').click();await shot('exceptions-light','Profile provenance in the exceptions list');
  fs.writeFileSync(join(out,'profiles.json'),JSON.stringify({steps,page_errors:errors,mobile_overflow_px:overflow},null,2));
  console.log(JSON.stringify({out,steps:steps.length,page_errors:errors.length,mobile_overflow_px:overflow}));if(errors.length||overflow)process.exitCode=1;
 }catch(e){console.error(e);process.exitCode=1;}finally{if(browser)await browser.close();fixture.kill('SIGTERM');await new Promise(r=>fixture.exitCode!==null?r():fixture.once('exit',r));}
})();
