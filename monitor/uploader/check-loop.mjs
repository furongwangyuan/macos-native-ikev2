import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {loop,pause,URL} from './uploader.mjs';
import {plist} from './install.mjs';
const HERE=path.dirname(fileURLToPath(import.meta.url));
const valid=()=>Buffer.from(JSON.stringify({schema_version:3,registry_revision:1,observed_at:'2026-10-22T23:02:00.000Z',
 collector:{state:'ok',started_at:'2026-10-22T23:00:00.000Z'},server:{state:'running'},
 coverage:{kind:'ipsec_child_counters',totals_scope:'calendar_day',timezone:'Asia/Kuala_Lumpur',day:'2026-10-23',day_started_at:'2026-10-22T16:00:00.000Z',observed_since:'2026-10-22T23:00:00.000Z',limitation:'当日已采样小计，可能遗漏'},
 devices:[{id:'device01',name:'测试',state:'offline',registration_state:'enabled',connected_since:null,rate_window_ms:null,upload_bps:null,download_bps:null,upload_bytes:'0',download_bytes:'24',totals_since:'2026-10-22T23:00:00.000Z',counter_epoch:'daily_fixture_20261023',counter_state:'partial'}]}));
async function simulate(statuses,{duration=0,read=valid,tokenError=false}={}){
 const stop=new AbortController(),starts=[],waits=[],published=[];let clock=0,calls=0,tokens=0,inFlight=0;
 await loop({signal:stop.signal,read,token:()=>{tokens++;if(tokenError)throw Error('PRIVATE');return 'FAKE_'+tokens;},clock:()=>clock,
 now:()=>new Date(1792710000000+clock).toISOString(),publish:r=>published.push(r),
 send:async(url,options)=>{assert.equal(inFlight++,0);assert.equal(url,URL);assert.equal(options.redirect,'error');starts.push(clock);clock+=duration;await Promise.resolve();inFlight--;return {status:statuses[calls++],body:{cancel:async()=>{}}};},
 wait:async ms=>{waits.push(ms);clock+=ms;if(waits.length>=statuses.length)stop.abort();}});
 return {starts,waits,published,tokens,calls};
}
test('one cached credential, one serial request each second',async()=>{
 const r=await simulate([204,204,204],{duration:250});assert.deepEqual(r.starts,[0,1000,2000]);assert.deepEqual(r.waits,[750,750,750]);assert.equal(r.tokens,1);assert.equal(r.published.length,1);
});
test('slow responses never overlap and no catch-up burst',async()=>{
 const r=await simulate([204,204],{duration:1300});assert.deepEqual(r.starts,[0,1300]);assert.deepEqual(r.waits,[0,0]);assert.equal(r.tokens,1);
});
test('failure backoff, success reset, auth credential refresh',async()=>{
 const r=await simulate([500,500,204,401,204]);assert.deepEqual(r.waits,[2000,4000,1000,60000,1000]);assert.equal(r.tokens,2);
 assert.equal(JSON.stringify(r.published).includes('FAKE_'),false);assert.equal(JSON.stringify(r.published).includes('PRIVATE'),false);
});
test('invalid schema never reads credential; missing credential retries only after sixty seconds',async()=>{
 const invalid=await simulate([0,0],{read:()=>Buffer.from('{"schema_version":2}')});assert.equal(invalid.tokens,0);assert.equal(invalid.calls,0);assert.deepEqual(invalid.waits,[2000,4000]);
 const missing=await simulate([0,0],{tokenError:true});assert.equal(missing.calls,0);assert.equal(missing.tokens,2);assert.deepEqual(missing.waits,[60000,60000]);assert.equal(JSON.stringify(missing).includes('PRIVATE'),false);
});
test('cancellation aborts active request and writes no fabricated final status',async()=>{
 const stop=new AbortController();let called=0,published=0;
 await loop({read:valid,token:()=> 'FAKE',signal:stop.signal,publish:()=>published++,send:async(_,opts)=>{called++;queueMicrotask(()=>stop.abort());return new Promise((resolve,reject)=>opts.signal.addEventListener('abort',()=>reject(Error('PRIVATE')),{once:true}));}});
 assert.equal(called,1);assert.equal(published,0);const timer=performance.now();await pause(60000,stop.signal);assert.ok(performance.now()-timer<1000);
});
test('unchanged disk diagnostic every fifteen seconds, upload every second',async()=>{
 const r=await simulate(Array(17).fill(204));assert.equal(r.calls,17);assert.equal(r.published.length,2);assert.equal(r.tokens,1);
});
test('persistent plist is generated for the current Node and a supplied user directory',()=>{
 const body=plist('/Users/example/Library/Application Support/Family VPN/Sites').toString();
 assert.match(body,/<key>KeepAlive<\/key><true\/>/);assert.doesNotMatch(body,/StartInterval/);
 assert.match(body,/<key>ThrottleInterval<\/key><integer>15<\/integer>/);
 assert.ok(body.includes(process.execPath));
});
