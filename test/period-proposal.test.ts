import test from 'node:test';
import assert from 'node:assert/strict';
import {proposedCreationPeriods,proposedFiveHourWindow,proposedWeeklyWindow,proposedRecurringBars} from '../server/period-proposal.js';
import {windowStart,nextReset} from '../server/store.js';
const hour=60*60*1000;
test('creation choices exclude daily/monthly',()=>{
 assert.deepEqual(proposedCreationPeriods,['never','5h','weekly']);
});
test('5h explicitly anchored fixed windows, boundaries and inactivity',()=>{
 const anchor=Date.parse('2026-11-22T03:45:24.224Z');
 assert.deepEqual(proposedFiveHourWindow(anchor,anchor),{start:anchor,reset:anchor+5*hour});
 assert.deepEqual(proposedFiveHourWindow(anchor+5*hour-1,anchor),{start:anchor,reset:anchor+5*hour});
 assert.deepEqual(proposedFiveHourWindow(anchor+5*hour,anchor),{start:anchor+5*hour,reset:anchor+10*hour});
 assert.deepEqual(proposedFiveHourWindow(anchor+105*hour+123,anchor),{start:anchor+105*hour+123,reset:anchor+110*hour+123});
 assert.throws(()=>proposedFiveHourWindow(anchor-1,anchor));
 for(const bad of [NaN,Infinity,-1,1.5,Number.MAX_SAFE_INTEGER])assert.throws(()=>proposedFiveHourWindow(bad,0));
 assert.throws(()=>proposedFiveHourWindow(anchor,undefined as unknown as number));
 assert.throws(()=>proposedFiveHourWindow(8_640_000_000_000_000,0));
});
test('weekly proposal equals existing runtime across month/year/leap/DST boundaries',()=>{
 for(const date of ['2026-11-22T05:39:51Z','2026-11-23T00:00:00Z','2027-01-01T00:00:00Z','2028-02-29T23:59:59Z','2026-03-08T10:00:00Z']){
  const now=Date.parse(date),w=proposedWeeklyWindow(now);
  assert.equal(w.start,windowStart('weekly',now));assert.equal(w.reset,nextReset('weekly',now));
 }
});
test('5h/weekly bars use own balance/reset and unrelated period is full',()=>{
 const reset=Date.parse('2026-11-23T00:00:00Z');
 assert.deepEqual(proposedRecurringBars('weekly',0.4,reset),{fiveHour:{fraction:1},weekly:{fraction:0.4,reset:new Date(reset).toISOString()}});
 assert.deepEqual(proposedRecurringBars('5h',0,reset),{fiveHour:{fraction:0,reset:new Date(reset).toISOString()},weekly:{fraction:1}});
 assert.equal(proposedRecurringBars('5h',-1,reset).fiveHour.fraction,0);
 assert.equal(proposedRecurringBars('weekly',2,reset).weekly.fraction,1);
 assert.throws(()=>proposedRecurringBars('weekly',NaN,reset));
});
