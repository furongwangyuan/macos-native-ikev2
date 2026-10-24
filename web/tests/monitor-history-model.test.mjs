import test from 'node:test';
import assert from 'node:assert/strict';
import {allDevices,selectDevice,normalizeHistory,availableDevices,historyWithLive,chartSeries,HISTORY_WINDOW_MS,USAGE_BUCKET_MS} from '../public/monitor/history-model.mjs';

const origin=Date.parse('2026-10-23T00:00:00.000Z');
const iso=time=>new Date(time).toISOString();
const device=(id,up,down,extra={})=>({id,name:id,upload_bytes:String(up),download_bytes:String(down),counter_epoch:'daily_first_20261023',counter_state:'partial',totals_since:iso(origin),...extra});
const point=(time,devices)=>({observed_at:iso(time),devices});
const at=(minute,devices)=>point(origin+minute*60000,devices);
const choices=[{id:'a',name:'Alice'},{id:'b',name:'Bob'}];
const series=(points,now,selection=allDevices())=>chartSeries(points,selection,choices,now)[0];
const known=result=>result.buckets.filter(b=>b.bytes!==null);
const unknown=device('a',0,0,{upload_bytes:null,download_bytes:null,counter_epoch:null,totals_since:null,counter_state:'unavailable'});

test('thirty-minute use is comparable counter deltas, with genuine zeros and right-closed buckets',()=>{
  const points=Array.from({length:31},(_,i)=>at(i,[device('a',100+i*10,200+i*20)]));
  const result=series(points,origin+30*60000);
  assert.equal(result.buckets.length,48);
  assert.deepEqual(known(result),[{time:origin+30*60000,start:origin,end:origin+30*60000,bytes:900n,partial:false}]);
  assert.equal(result.last.bytes,900n);
  assert.equal(known(series(points.slice(0,1),origin+30*60000)).length,0);
  const zero=series([at(0,[device('a',10,10)]),at(1,[device('a',10,10)])],origin+2*60000);
  assert.equal(zero.last.bytes,0n);assert.equal(zero.last.partial,true);
  // A valid interval crossing a bucket boundary is entirely attributed to its end bucket.
  const cross=series([point(origin+1790000,[device('a',10,10)]),point(origin+1850000,[device('a',20,30)])],origin+3600000);
  assert.equal(known(cross)[0].start,origin+1800000);assert.equal(known(cross)[0].bytes,30n);
});

test('rolling history spans two Malaysian dates but never subtracts across midnight epochs',()=>{
  const midnight=Date.parse('2026-10-23T16:00:00.000Z');
  const before=device('a',100,200);
  const after=device('a',5,10,{counter_epoch:'daily_second_20261024',totals_since:iso(midnight)});
  const points=[point(midnight-60000,[before]),point(midnight,[after]),point(midnight+60000,[{...after,upload_bytes:'15',download_bytes:'30'}])];
  const result=series(points,midnight+120000);
  assert.equal(known(result).length,1);assert.equal(result.last.bytes,30n);assert.equal(result.last.partial,true);
  const history={days:['2026-10-23','2026-10-24'],points};
  assert.equal(historyWithLive(history,null,false,midnight+120000).length,3);
  assert.deepEqual(availableDevices(history,null,midnight+120000),[{id:'a',name:'a'}]);
});

test('missing intervals, either counter decreasing, and unknown values do not become traffic or zero',()=>{
  const first=device('a',20,30);
  for(const invalid of [
    at(2,[device('a',30,50)]), // More than 90 seconds.
    at(1,[device('a',19,100)]), // Upload reset cannot hide behind download increase.
    at(1,[device('a',100,29)]),
    at(1,[unknown]),
    at(1,[device('a',30,50,{totals_since:iso(origin+1000)})]),
    at(1,[device('a',30,50,{counter_epoch:'other'})])
  ])assert.equal(known(series([at(0,[first]),invalid],origin+30*60000)).length,0);
  const points=[at(0,[first]),at(1,[device('a',30,40)]),at(2,[unknown]),at(3,[device('a',40,50)]),at(4,[device('a',50,60)])];
  assert.equal(series(points,origin+30*60000).last.bytes,40n);
  assert.equal(series(points,origin+30*60000).last.partial,true);
  const separated=series([at(0,[first]),at(1,[device('a',30,40)]),at(61,[device('a',40,50)]),at(62,[device('a',50,60)])],origin+90*60000);
  assert.equal(separated.segments.length,2);
  assert.equal(series([at(0,[]),at(1,[])],origin+30*60000).last,null);
});

test('window keeps one baseline but excludes straddling/outside intervals; live points are fresh and bounded',()=>{
  const now=origin+HISTORY_WINDOW_MS+30000,start=now-HISTORY_WINDOW_MS;
  const points=[point(start-120000,[device('old',1,1)]),point(start-30000,[device('a',10,10)]),point(start+30000,[device('a',20,20)]),point(start+90000,[device('a',30,40)]),point(now+1000,[device('future',1,1)])];
  const history={points,days:[]};
  const trimmed=historyWithLive(history,null,false,now);
  assert.equal(trimmed.length,3);assert.equal(Date.parse(trimmed[0].observed_at),start-30000);
  const result=series(trimmed,now);
  assert.equal(result.buckets.length,49);
  assert.equal(result.buckets[0].start,start);assert.equal(result.buckets.at(-1).end,now);
  assert.equal(known(result)[0].bytes,30n);assert.equal(known(result)[0].partial,true);
  assert.equal(result.last,null); // Old known data is not presented as the current period.
  assert.deepEqual(availableDevices(history,null,now),[{id:'a',name:'a'}]);
  const snapshot={collector:{state:'ok'},observed_at:iso(now),devices:[device('a',40,50)]};
  assert.equal(historyWithLive(history,snapshot,false,now).length,3);
  assert.equal(historyWithLive(history,snapshot,true,now).length,4);
  const merged=historyWithLive({points:[...trimmed,point(now,[device('a',39,49)])]},snapshot,true,now);
  assert.equal(merged.length,4);assert.equal(merged.at(-1).devices[0].upload_bytes,'40');
});

test('all-device intervals require the same roster; device selections stay independent and empty stays empty',()=>{
  const points=[at(0,[device('a',100,100)]),at(1,[device('a',110,120),device('b',1000,1000)]),at(2,[device('a',120,140),device('b',1010,1020)]),at(3,[device('a',130,160)])];
  assert.equal(series(points,origin+30*60000).last.bytes,60n); // Only the unchanged-roster interval.
  let selected=selectDevice(allDevices(),'a',true);
  assert.deepEqual(selected,{mode:'selected',ids:['a']});
  assert.equal(series(points,origin+30*60000,selected).last.bytes,90n);
  selected=selectDevice(selected,'b',true);
  assert.deepEqual(chartSeries(points,selected,choices,origin+30*60000).map(s=>s.last.bytes),[90n,30n]);
  selected=selectDevice(selectDevice(selected,'a',false),'b',false);
  assert.deepEqual(chartSeries(points,selected,choices,origin+30*60000),[]);
  assert.equal(chartSeries(points,allDevices(),choices,origin+30*60000).length,1);
  const raw={version:1,day:'2026-10-23',timezone:'Asia/Kuala_Lumpur',interval_seconds:60,started_at:iso(origin),points:[points[0]]};
  assert.equal(normalizeHistory(raw,raw.day).points.length,1);
  assert.throws(()=>normalizeHistory({...raw,points:[at(0,[{...unknown,upload_bytes:'0'}])]},raw.day));
  assert.equal(USAGE_BUCKET_MS,1800000);
});
