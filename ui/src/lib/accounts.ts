export type QuotaBucket={family:string;label?:string;remaining?:number;reset?:number;disabled?:boolean};
export const accountFamilies=[['gemini','Gemini'],['claude','Claude & GPT'],['argon','Argon']] as const;
export function quotaWindow(label=''){
 if(/\b(weekly|week)\b/i.test(label))return 'Week';
 if(/\b5\s*h\b|five[ -]?hour/i.test(label))return '5h';
 return label||'Quota';
}
export function quotaLevel(remaining?:number){return typeof remaining!=='number'||!Number.isFinite(remaining)?'unknown':remaining>=.5?'high':remaining>=.2?'medium':'low';}
export function relativeReset(reset?:number,now=Date.now()){
 if(!reset||!Number.isFinite(reset))return 'Unknown reset';
 const minutes=Math.ceil((reset-now)/60000);
 if(minutes<=0)return 'Reset due';
 if(minutes<60)return 'in '+minutes+'m';
 const hours=Math.ceil(minutes/60);
 return hours<24?'in '+hours+'h':'in '+Math.ceil(hours/24)+'d';
}
