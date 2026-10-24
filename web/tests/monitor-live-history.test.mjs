import test from 'node:test';
import assert from 'node:assert/strict';
import {allDevices,retainLivePoints,historyWithLive,chartSeries,RECENT_LIVE_WINDOW_MS,MAX_RECENT_LIVE_POINTS} from '../public/monitor/history-model.mjs';

const origin=Date.parse('2026-10-24T00:00:00.000Z');
const iso=time=>new Date(time).toISOString();
const device=(value,extra={})=>({id:'a',name:'Alice',upload_bytes:String(value),download_bytes:'0',counter_epoch:'daily_first_20261024',counter_state:'partial',totals_since:iso(origin),...extra});
const snapshot=(second,value=second*10,extra={})=>({collector:{state:'ok'},observed_at:iso(origin+second*1000),devices:[device(value,extra)]});
const historyPoint=s=>({observed_at:s.observed_at,devices:s.devices});
const result=(history,recent,current,second,fresh=true)=>chartSeries(historyWithLive(history,current,fresh,origin+second*1000,recent),allDevices(),[{id:'a',name:'Alice'}],origin+second*1000)[0];
const known=sum=>sum.buckets.reduce((total,b)=>total+(b.bytes??0n),0n);

test('continuous fresh observations survive a late minute-history refresh and deduplicate its catch-up',()=>{
  let recent=[];
  const history={points:[historyPoint(snapshot(0))]};
  for(let second=0;second<=119;second++) {
    const current=snapshot(second);
    recent=retainLivePoints(recent,current,true,origin+second*1000);
    if(second>0)assert.equal(result(history,recent,current,second).last.bytes,BigInt(second*10));
  }
  // The old implementation loses the entire visible interval at second 91.
  assert.equal(result(history,[],snapshot(91),91).last,null);
  history.points.push(historyPoint(snapshot(60)),historyPoint(snapshot(120)));
  recent=retainLivePoints(recent,snapshot(120),true,origin+120000);
  assert.equal(result(history,recent,snapshot(120),120).last.bytes,1200n);
});

test('a genuine gap beyond 90 seconds remains unknown instead of becoming traffic or zero',()=>{
  const first=snapshot(0),later=snapshot(91);
  let recent=retainLivePoints([],first,true,origin);
  recent=retainLivePoints(recent,later,true,origin+91000);
  assert.equal(result({points:[historyPoint(first)]},recent,later,91).last,null);
  recent=retainLivePoints(recent,snapshot(92),true,origin+92000);
  const recovered=result(null,recent,snapshot(92),92);
  assert.equal(recovered.last.bytes,10n);
  assert.equal(recovered.last.partial,true);
  assert.equal(result(null,[historyPoint(first)],snapshot(90),90).last.bytes,900n);
});

test('stale or unavailable responses do not add cache points or bridge a genuine outage',()=>{
  let recent=retainLivePoints([],snapshot(0),true,origin);
  recent=retainLivePoints(recent,snapshot(30),false,origin+30000);
  recent=retainLivePoints(recent,{...snapshot(60),collector:{state:'unavailable'}},true,origin+60000);
  assert.equal(recent.length,1);
  recent=retainLivePoints(recent,snapshot(100),true,origin+100000);
  assert.equal(result(null,recent,snapshot(100),100).last,null);
});

test('midnight and same-day epoch changes never subtract across counter identities',()=>{
  const midnight=Date.parse('2026-10-24T16:00:00.000Z');
  const points=[
    {collector:{state:'ok'},observed_at:iso(midnight-1000),devices:[device(100)]},
    {collector:{state:'ok'},observed_at:iso(midnight),devices:[device(5,{counter_epoch:'daily_second_20261025',totals_since:iso(midnight)})]},
    {collector:{state:'ok'},observed_at:iso(midnight+1000),devices:[device(15,{counter_epoch:'daily_second_20261025',totals_since:iso(midnight)})]},
  ];
  let recent=[];
  for(const point of points)recent=retainLivePoints(recent,point,true,Date.parse(point.observed_at));
  const merged=historyWithLive({points:points.map(historyPoint)},points.at(-1),true,midnight+1000,recent);
  assert.equal(known(chartSeries(merged,allDevices(),[],midnight+1000)[0]),10n);
  recent=[];
  for(const [second,value,epoch] of [[0,100,'old'],[1,5,'new'],[2,15,'new']])
    recent=retainLivePoints(recent,snapshot(second,value,{counter_epoch:epoch}),true,origin+second*1000);
  assert.equal(known(result(null,recent,null,2,false)),10n);
});

test('duplicate renders and overlapping minute observations count each interval once',()=>{
  let recent=[];
  for(const second of [0,1,1,1,2,2])recent=retainLivePoints(recent,snapshot(second),true,origin+second*1000);
  assert.equal(recent.length,3);
  const history={points:[0,1,2].map(second=>historyPoint(snapshot(second)))};
  assert.equal(historyWithLive(history,snapshot(2),true,origin+2000,recent).length,3);
  assert.equal(result(history,recent,snapshot(2),2).last.bytes,20n);
  // A delayed, real observation is sorted; it does not add its lifetime bytes.
  recent=retainLivePoints(recent,snapshot(0.5,5),true,origin+2000);
  assert.equal(result(history,recent,snapshot(2),2).last.bytes,20n);
});

test('cache copies only history fields, ignores future points, and is bounded by age and count',()=>{
  const first=snapshot(0);
  first.devices[0].upload_bps=999;
  let recent=retainLivePoints([],first,true,origin);
  first.devices[0].upload_bytes='999';
  assert.equal(recent[0].devices[0].upload_bytes,'0');
  assert.equal(Object.hasOwn(recent[0].devices[0],'upload_bps'),false);
  recent=retainLivePoints(recent,snapshot(1),true,origin);
  assert.equal(recent.length,1);
  const now=origin+RECENT_LIVE_WINDOW_MS+1;
  assert.equal(retainLivePoints(recent,null,false,now).length,0);
  for(let i=0;i<1000;i++)recent=retainLivePoints(recent,snapshot(i/100,i),true,origin+i*10);
  assert.equal(recent.length,MAX_RECENT_LIVE_POINTS);
  assert.equal(Date.parse(recent[0].observed_at),origin+4000);
});
