import {test} from 'node:test';
import assert from 'node:assert/strict';
import {quotaWindow,quotaLevel,relativeReset} from '../ui/src/lib/accounts.js';
test('account quota labels never invent missing windows and level boundaries match demo',()=>{
 assert.equal(quotaWindow('Gemini Models · Five Hour Limit Remaining · gemini-5h · 5h'),'5h');
 assert.equal(quotaWindow('Gemini 4 Argon Weekly Limit · weekly'),'Week');
 assert.equal(quotaWindow('Custom window'),'Custom window');
 assert.equal(quotaLevel(.5),'high');assert.equal(quotaLevel(.2),'medium');assert.equal(quotaLevel(.19),'low');assert.equal(quotaLevel(undefined),'unknown');assert.equal(quotaLevel(NaN),'unknown');
});
test('account resets are relative and honest about absent data',()=>{
 assert.equal(relativeReset(0,100),'Unknown reset');assert.equal(relativeReset(100,100),'Reset due');
 assert.equal(relativeReset(60000,0),'in 1m');assert.equal(relativeReset(3600000,0),'in 1h');assert.equal(relativeReset(86400000,0),'in 1d');
});
