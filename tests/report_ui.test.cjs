const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const source = fs.readFileSync('app/static/app.js', 'utf8');
function harness(period, usage = true, failCompanion = false) {
 const elements = {};
 for (const id of ['executiveReport','executivePeriod','executiveSection','executiveSearch','executiveTable','executivePage','executivePrev','executiveNext']) elements['#'+id] = {value:'',dataset:{},isConnected:true,innerHTML:''};
 const links = ['xlsx','pdf','html'].map(format=>({dataset:{reportFormat:format}}));
 elements['#executiveReport'].dataset.usagePage = usage?'1':'';
 elements['#executiveReport'].querySelectorAll = ()=>links;
 elements['#executivePeriod'].value = period;
 elements['#executivePeriod'].options = ['2026-08','Copilot - month 2026-08'].map(value=>({value}));
 elements['#executiveSection'].value = '0';
 const context = vm.createContext({$:id=>elements[id],esc:String,number:String,money:n=>'$'+n,Date,encodeURIComponent,
  api:async url=>{
   const selected = decodeURIComponent(url.split('period=')[1]);
   if(failCompanion && selected!==period) throw Error('Unavailable');
   const provider = selected.startsWith('Copilot')?'Copilot':'Claude';
   return {summary:{},charts_html:`<div>${provider} chart</div>`,executive_sections:[{name:'Department Summary',rows:[['Department','Adoption'],[provider+' department',0.5]],formats:[[],['General','0.0%']]}]};
  }});
 vm.runInContext(source.slice(source.indexOf('async function loadExecutiveReport()')),context);
 return {elements,links,context};
}
test('Both providers share sections below ordered graphs, and exports follow selection',async()=>{
 const {elements:e,links,context}=harness('2026-08');
 await context.loadExecutiveReport();
 const html=e['#executiveReport'].innerHTML;
 assert.ok(html.indexOf('Claude chart')<html.indexOf('Copilot chart'));
 assert.ok(html.indexOf('Copilot chart')<html.indexOf('id="executiveSection"'));
 // Provider colour is styled from the section, never from the selected period.
 assert.ok(html.includes('class="provider-overview" data-provider="claude"'));
 assert.ok(html.includes('class="provider-overview" data-provider="copilot"'));
 assert.ok(!html.includes('Microsoft 365 Copilot - Copilot'));
 assert.ok(html.includes('Copilot - Department Summary'));
 assert.ok(!html.includes('View Copilot details'));
 assert.ok(e['#executiveTable'].innerHTML.includes('Claude department'));
 e['#executiveSection'].value='1';e['#executiveSection'].onchange();
 assert.ok(e['#executiveTable'].innerHTML.includes('Copilot department'));
 assert.ok(e['#executiveTable'].innerHTML.includes('50%'));
 for(const link of links) assert.ok(link.href.includes('period=Copilot%20-%20month%202026-08'));
 e['#executiveSearch'].value='missing';e['#executiveSearch'].oninput();
 assert.ok(!e['#executiveTable'].innerHTML.includes('Copilot department'));
});
test('Historical reports and Copilot-first selection retain both providers',async()=>{
 const {elements:e,links,context}=harness('Copilot - month 2026-08',false);
 await context.loadExecutiveReport();
 assert.ok(e['#executiveReport'].innerHTML.includes('Claude - Department Summary'));
 assert.ok(e['#executiveReport'].innerHTML.includes('class="provider-overview" data-provider="claude"'));
 assert.ok(e['#executiveReport'].innerHTML.includes('class="provider-overview" data-provider="copilot"'));
 assert.ok(links.every(link=>link.href.startsWith('/api/reports/executive?period=2026-08')));
});
test('Companion failure preserves the available report',async()=>{
 const {elements:e,context}=harness('2026-08',true,true);
 await context.loadExecutiveReport();
 assert.ok(e['#executiveReport'].innerHTML.includes('Companion report could not be loaded'));
 assert.ok(e['#executiveTable'].innerHTML.includes('Claude department'));
});
