// OFFLINE PROPOSAL ONLY. Intentionally not imported by production code.
// An explicit persisted request anchor is required. This is not a migration.
export const proposedCreationPeriods = ['never','5h','weekly'] as const;
const FIVE_HOURS = 5 * 60 * 60 * 1000;
const MAX_DATE = 8_640_000_000_000_000;
function timestamp(value:number){
 if(!Number.isSafeInteger(value)||value<0||value>MAX_DATE)throw new RangeError('Invalid period timestamp');
 return value;
}
export function proposedFiveHourWindow(now:number,anchor:number){
 timestamp(now);timestamp(anchor);
 if(now<anchor)throw new RangeError('Period anchor is in the future');
 const start=now>=anchor+FIVE_HOURS?now:anchor;
 const reset=timestamp(start+FIVE_HOURS);
 return {start,reset};
}
// Preserves current Monday 00:00 UTC weekly semantics, independent of locale/DST.
export function proposedWeeklyWindow(now:number){
 timestamp(now);const d=new Date(now);d.setUTCHours(0,0,0,0);
 d.setUTCDate(d.getUTCDate()-(d.getUTCDay()+6)%7);
 return {start:+d,reset:timestamp(+d+7*24*60*60*1000)};
}
export function proposedRecurringBars(period:'5h'|'weekly',fraction:number,reset:number){
 if(!Number.isFinite(fraction))throw new RangeError('Invalid remaining fraction');
 timestamp(reset);
 const selected={fraction:Math.max(0,Math.min(1,fraction)),reset:new Date(reset).toISOString()};
 // The unrelated period is full, without an invented reset or underlying pool quota.
 return period==='5h'?{fiveHour:selected,weekly:{fraction:1}}:{fiveHour:{fraction:1},weekly:selected};
}
