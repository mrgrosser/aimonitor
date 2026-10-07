const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('app/static/app.js', 'utf8');
function harness() {
 const buttons = {'[data-cancel]':{}, '[data-continue]':{}};
 const dialog = {setAttribute(){}, querySelector:s=>buttons[s], showModal(){this.shown=true}, close(){}, remove(){this.removed=true}};
 const context = vm.createContext({document:{activeElement:{focus(){}},createElement:()=>dialog,body:{appendChild(){}}}});
 vm.runInContext(source.slice(source.indexOf('let sensitiveAccessPending'), source.indexOf('function caseStatusLabel')),context);
 return {context,dialog,buttons};
}
test('Sensitive access requires an explicit Continue; Cancel and Escape decline',async()=>{
 for (const action of ['cancel','escape','continue']) {
  const {context,dialog,buttons} = harness();
  const pending=context.confirmSensitiveAccess();
  assert.equal(dialog.shown,true);
  assert.match(dialog.innerHTML,/Your access will be logged/);
  assert.equal(await context.confirmSensitiveAccess(),false);
  if(action==='escape')dialog.oncancel({preventDefault(){}});
  else buttons[`[data-${action}]`].onclick();
  assert.equal(await pending,action==='continue');
  assert.equal(dialog.removed,true);
 }
});
