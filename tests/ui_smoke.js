async (page) => {
 const assert = (condition, message) => { if (!condition) throw new Error(message); };
 const base='http://127.0.0.1:18483/plugin.ui/org.zoraxy.waf/';
 const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 // Plain-HTTP LAN management pages do not expose crypto.randomUUID.
 await page.addInitScript(()=>Object.defineProperty(Crypto.prototype,'randomUUID',{value:undefined,configurable:true}));
 await page.goto(base);await page.locator('#notice').filter({hasText:'Saved configuration loaded'}).waitFor();
 assert(await page.locator('#hero-sub').textContent().then(s=>s.includes('coraza')), 'Coraza engine missing from hero');
 assert(await page.locator('#hero').getAttribute('class').then(c=>c.includes('state-off')), 'Fresh install must show inspection off');
 assert(await page.locator('#protection-ring text').textContent().then(t=>/^\d+ %$/.test(t)), 'Protection ring without percentage');
 assert(await page.locator('#protection-list li.missing').count()>=1, 'Off mode must list a missing protection item');
 assert(await page.locator('#chart-hours svg rect').count()>=24, 'Hourly chart has no bars');
 assert(await page.locator('#chart-days svg rect').count()>=30, 'Daily chart has no bars');
 assert(await page.locator('#chart-categories svg').count()===1 && await page.locator('#top-hosts').textContent().then(t=>t.includes('No attacks')), 'Empty-state charts missing');
 await page.locator('[data-tab="settings"]').click();await page.locator('#mode').selectOption('report');
 await page.locator('#settings-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 1 saved'}).waitFor();
 assert((await page.locator('#notice').textContent()).includes('Adoption pending'), 'Save falsely confirms core adoption instead of pending propagation');
 await page.locator('[data-tab="hosts"]').click();await page.locator('#host-key').fill('shop.example');await page.locator('#host-mode').selectOption('report');await page.locator('#host-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 2 saved'}).waitFor();
 await page.locator('#failure-hosts').fill('shop.example');await page.locator('#failure-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 3 saved'}).waitFor();
 const payload={method:'GET',host:'shop.example',hostname:'shop.example',request_uri:'/search?q='+encodeURIComponent('<script>alert(1)</script>'),proto:'HTTP/1.1',client_ip:'203.0.113.10',remote_addr:'203.0.113.10:4000',route_id:'shop.example',protocol_version:1,header:{'User-Agent':['Mozilla/5.0'],'Accept':['text/html'],'Accept-Language':['en-US']}};
 let response=await page.request.post('http://127.0.0.1:18482/inspect',{data:payload});let decision=await response.json();assert(decision.action==='allow'&&decision.event_id,'Report-only attack did not allow with event');
 const eventID=decision.event_id;
 await page.locator('[data-tab="settings"]').click();assert(await page.locator('#changes table tbody tr').count()>=1,'Change history empty after a save');
 assert(await page.locator('#changes').textContent().then(t=>t.includes('mode')&&t.includes('off → report')),'Change history must list the mode change');
 assert(await page.locator('#mode-impact').textContent().then(t=>t.includes('Report only')),'Mode impact text missing');
 await page.locator('#mode').selectOption('block');assert(await page.locator('#mode-impact').textContent().then(t=>t.includes('Changing report → block')),'Mode change preview missing');await page.locator('#mode').selectOption('report');
 await page.locator('[data-tab="alerts"]').click();await page.locator('#sink-name').fill('Chat');await page.locator('#sink-url').fill('http://127.0.0.1:18483/hook');await page.locator('#sink-add').click();
 assert(await page.locator('#sinks tbody tr').count()===1,'Receiver not added');await page.locator('#alerts-enabled').check();await page.locator('#alerts-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 4 saved'}).waitFor();
 await page.locator('#alerts-test').click();await page.locator('#notice').filter({hasText:'Test alert delivered'}).waitFor({timeout:20000});assert(await page.locator('#alerts-status').textContent().then(t=>/Delivered 1 · failed 0/.test(t)),'Alert delivery counters missing');
 await page.locator('[data-tab="overview"]').click();await page.locator('#hm-today').filter({hasText:/^[1-9]/}).waitFor();
 assert(await page.locator('#hero').getAttribute('class').then(c=>c.includes('state-warn')), 'Report mode must show the learning (warn) hero');
 assert(await page.locator('#chart-categories').textContent().then(t=>t.includes('Cross-site scripting')), 'XSS attack missing from attack types');
 assert(await page.locator('#top-hosts').textContent().then(t=>t.includes('shop.example')) && await page.locator('#top-ips').textContent().then(t=>t.includes('203.0.113.10')), 'Rankings missing host/IP');
 await page.locator('#top-ips button.rank-action').first().click();assert(await page.locator('#filter-ip').inputValue()==='203.0.113.10' && !(await page.locator('#events').isHidden()), 'IP ranking action did not open filtered events');await page.locator('#filter-ip').fill('');
 await page.locator('[data-tab="settings"]').click();await page.locator('#mode').selectOption('off');
 assert(await page.locator('#mode-impact').textContent().then(t=>/In the last 24 hours \d+ attacks? on \d+ hosts? would have reached your sites unseen/.test(t)), 'Loss picture from real numbers missing when switching to off');await page.locator('#mode').selectOption('report');
 await page.locator('[data-tab="events"]').click();await page.locator('#event-list tbody tr').first().waitFor();
 assert(await page.locator('#event-list').textContent().then(t=>t.includes('Cross-site scripting')&&t.includes('203.0.113.10')&&/\d+ (s|min) ago/.test(t)), 'Events table must show category, client IP and relative time');
 await page.locator('#chips [data-chip="blocked"]').click();await page.waitForTimeout(300);assert(await page.locator('#event-list').textContent().then(t=>t.includes('No entries')), 'Blocked chip must filter out the would_block event');
 await page.locator('#chips [data-chip=""]').click();await page.locator('#event-list tbody tr').first().waitFor();
 await page.locator('#filter-host').fill('shop.example');await page.locator('#filter-form button[type="submit"]').click();await page.locator('#event-list').filter({hasText:'would_block'}).waitFor();
 await page.locator('#event-list button').filter({hasText:'Suggest exception'}).first().click();await page.locator('#learning-list button').filter({hasText:'Review draft'}).first().click();
 assert(await page.locator('#exception-path').inputValue()==='/search','Suggestion not path-scoped');
 await page.locator('#exception-reason').fill('Reviewed false-positive test case');await page.locator('#exception-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 5 saved'}).waitFor();
 let state=await (await page.request.get(base+'api/state')).json();assert(state.config.exceptions.length===1,'Exception was not explicitly saved');assert(state.config.invert_failure_hosts[0]==='shop.example','Failure inversion not saved');
 // Delete the reviewed exception, then enforce the host in block mode.
 page.once('dialog',d=>d.accept());await page.locator('#exception-list button').filter({hasText:'Remove'}).click();await page.locator('#notice').filter({hasText:'revision 6 saved'}).waitFor();
 await page.locator('[data-tab="hosts"]').click();await page.locator('#host-mode').selectOption('block');await page.locator('#host-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 7 saved'}).waitFor();
 response=await page.request.post('http://127.0.0.1:18482/inspect',{data:payload});decision=await response.json();assert(decision.action==='deny'&&decision.status===403,'Block host did not deny attack');
 await page.locator('[data-tab="events"]').click();await page.locator('#filter-action').selectOption('blocked');await page.locator('#filter-form button[type="submit"]').click();await page.locator('#event-list').filter({hasText:'blocked · WAF'}).waitFor();
 await page.locator('#event-list button').filter({hasText:'Details'}).first().click();const detailRow=page.locator('#event-list tr.detail-row');assert(await detailRow.count()===1&&(await detailRow.textContent()).includes('"engine": "coraza"'),'Event detail must open inline under the row');
 assert(await page.evaluate(()=>{const r=document.querySelector('#event-list tr.detail-row');return r.previousElementSibling&&r.previousElementSibling.querySelector('button')!==null;}),'Detail row must sit directly under the clicked event row');
 await page.waitForTimeout(3500);assert(await detailRow.count()===1,'Inline detail must survive the live refresh');
 await page.locator('#event-list button').filter({hasText:'Close'}).first().click();assert(await detailRow.count()===0,'Close must remove the inline detail');
 // Saving an exception with a rejected scope must surface the server error visibly (sticky notice)
 await page.locator('[data-tab="exceptions"]').click();await page.locator('#exception-rule').fill('941100');await page.locator('#exception-host').fill('shop.example');await page.locator('#exception-path').fill('/x');await page.locator('#exception-reason').fill('abc');await page.locator('#exception-expiry').fill('2020-01-01T00:00');await page.locator('#exception-form button[type="submit"]').click();
 assert(await page.locator('#notice.negative').textContent().then(t=>t.includes('Expiry must be in the future')),'Rejected exception must show a visible error');await page.locator('#exception-cancel').click();await page.locator('[data-tab="events"]').click();
 const exported=await page.request.get(await page.locator('#export').getAttribute('href').then(x=>base+x));assert(exported.status()===200&&(await exported.text()).includes('"action":"blocked"'),'Filtered export missing block');
 // The default-site sentinel is editable in the UI, but not arbitrary path keys.
 await page.locator('[data-tab="hosts"]').click();await page.locator('#host-key').fill('/');await page.locator('#host-mode').selectOption('block');await page.locator('#host-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 8 saved'}).waitFor();
 await page.locator('#failure-hosts').fill('shop.example\n/');await page.locator('#failure-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 9 saved'}).waitFor();
 state=await (await page.request.get(base+'api/state')).json();assert(state.config.hosts['/'].mode==='block'&&state.config.invert_failure_hosts.includes('/'),'Root override/failure inversion not persisted by UI');
 await page.locator('#host-key').fill('/api');await page.locator('#host-form button[type="submit"]').click();await page.locator('#notice[role="alert"]').waitFor();assert((await page.locator('#notice').textContent()).includes('Configuration rejected'), 'Arbitrary path key not rejected');
 state=await (await page.request.get(base+'api/state')).json();assert(state.config.revision===9&&!state.config.hosts['/api'],'Rejected path key mutated configuration');
 const expected400='Failed to load resource: the server responded with a status of 400 (Bad Request)';assert(errors.filter(e=>e===expected400).length===1,'Expected one validation HTTP 400');errors.splice(errors.indexOf(expected400),1);
 // Capability gating must update without ever contacting an AppSec origin.
 await page.locator('[data-tab="settings"]').click();await page.locator('#engine').selectOption('crowdsec');assert(await page.locator('#coraza-settings').isHidden(),'Unsupported paranoia settings visible');assert(await page.locator('#crowdsec-settings').isVisible(),'AppSec settings missing');await page.locator('#engine').selectOption('coraza');
 // Measured-performance panel is static, labelled as a lab measurement and visible on Overview.
 await page.locator('[data-tab="overview"]').click();assert(!(await page.locator('#measured').isVisible()),'Lab panel must be collapsed by default');await page.locator('details.lab summary').click();const measured=await page.locator('#measured').textContent();assert(await page.locator('#measured').isVisible()&&measured.includes('Lab measurement')&&measured.includes('5671')&&measured.includes('774'),'Measured performance panel missing or unlabelled');
 // Speed level: four radio levels with lab values, default 400 active at runtime, change applied at once (gc_percent read back).
 await page.locator('[data-tab="settings"]').click();const help=await page.locator('#speed-help').textContent();assert(help.includes('Same rules, same detection')&&help.split(/[.!?](\s|$)/).filter(s=>s&&s.trim()).length<=3,'Speed explanation missing or longer than 3 sentences');
 const table=await page.locator('#speed-table').textContent();assert(['766','806','828','835','58 MiB','122 MiB','202 MiB','default'].every(x=>table.includes(x)),'Speed table incomplete');assert((await page.locator('#speed-cores').textContent()).includes('available now'),'CPU core hint missing');
 state=await (await page.request.get(base+'api/state')).json();assert(state.config.gc_target===400&&state.gc_percent===400&&await page.locator('input[name="gc-target"][value="400"]').isChecked()&&await page.locator('#speed-inactive').isHidden(),`Default level 400 not active: ${state.gc_percent}`);
 await page.locator('input[name="gc-target"][value="800"]').check();await page.locator('#settings-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 10 saved'}).waitFor();
 state=await (await page.request.get(base+'api/state')).json();assert(state.config.gc_target===800&&state.gc_percent===800,`Level 800 not active at runtime: ${state.gc_percent}`);assert((await page.locator('#speed-active').textContent()).includes('800'),'Active level not shown');
 await page.locator('input[name="gc-target"][value="100"]').check();await page.locator('#settings-form button[type="submit"]').click();await page.locator('#notice').filter({hasText:'revision 11 saved'}).waitFor();
 state=await (await page.request.get(base+'api/state')).json();assert(state.config.gc_target===100&&state.gc_percent===100,'Level 100 not applied');
 response=await page.request.post('http://127.0.0.1:18482/inspect',{data:payload});decision=await response.json();assert(decision.action==='deny'&&decision.status===403,'Detection changed after speed level change');
 await page.setViewportSize({width:390,height:844});await page.locator('[data-tab="events"]').click();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'Mobile page overflows horizontally');assert(await page.locator('#event-list').isVisible(),'Mobile event table hidden');
 await page.locator('[data-tab="overview"]').click();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'Mobile overview (measured performance) overflows horizontally');
 await page.locator('[data-tab="settings"]').click();assert(await page.locator('#speed-table').isVisible()&&await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'Mobile speed table hidden or overflowing');
 // No mutation without the browser echo; direct UI cannot bypass the proxy.
 assert((await page.request.put(base+'api/config',{data:state.config})).status()===403,'Missing CSRF echo accepted');assert((await page.request.get('http://127.0.0.1:18482/ui/api/state')).status()===403,'Direct admin accessible');
 assert(errors.length===0,'Browser errors: '+errors.join('; '));
 return {passed:true,journey:'global report → host report → failure list → real CRS event → suggested exception approval/delete → host block → filtered details/export → capability gating → measured-performance panel → speed levels 400 default/800/100 with runtime GC read-back + core hint and unchanged block → mobile → CSRF/direct-admin negatives',event_id:eventID,console_errors:errors};
}
