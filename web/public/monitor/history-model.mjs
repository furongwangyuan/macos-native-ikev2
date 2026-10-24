import {malaysiaDay} from './model.mjs';

export const HISTORY_POLL_MS = 60000;
const invalid = () => { throw new TypeError('invalid_history_contract'); };
const date = value => {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) return invalid();
  return new Date(value).toISOString();
};
const bytes = value => value === null || (typeof value === 'string' && /^(0|[1-9][0-9]{0,29})$/.test(value));
export const allDevices = () => ({mode:'all',ids:[]});
export function selectDevice(selection,id,checked) {
  const ids = new Set(selection.mode === 'all' ? [] : selection.ids);
  if (checked) ids.add(id); else ids.delete(id);
  return {mode:'selected',ids:[...ids]};
}
export function normalizeHistory(raw,day) {
  if (!raw || raw.version !== 1 || raw.day !== day || raw.timezone !== 'Asia/Kuala_Lumpur' || raw.interval_seconds !== 60 || !Array.isArray(raw.points) || raw.points.length > 1440) return invalid();
  const started = raw.started_at === null ? null : date(raw.started_at);
  let previous = -Infinity;
  const points = raw.points.map(point => {
    if (!point || !Array.isArray(point.devices) || point.devices.length > 16) return invalid();
    const observed_at = date(point.observed_at), time = Date.parse(observed_at);
    if (time <= previous || malaysiaDay(time) !== day) return invalid();
    previous = time;
    const ids = new Set();
    const devices = point.devices.map(d => {
      if (!d || typeof d.id !== 'string' || !/^[A-Za-z0-9_-]{1,48}$/.test(d.id) || ids.has(d.id) || typeof d.name !== 'string' || [...d.name].length < 1 || [...d.name].length > 80 || /[\u0000-\u001f\u007f]/u.test(d.name) || !bytes(d.upload_bytes) || !bytes(d.download_bytes) || !['partial','unavailable'].includes(d.counter_state)) return invalid();
      ids.add(d.id);
      if (d.counter_state === 'unavailable') {
        if ([d.upload_bytes,d.download_bytes,d.counter_epoch,d.totals_since].some(v => v !== null)) return invalid();
      } else {
        if (d.upload_bytes === null || d.download_bytes === null || typeof d.counter_epoch !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(d.counter_epoch) || !d.totals_since) return invalid();
        const since = date(d.totals_since);
        if (Date.parse(since) > time || malaysiaDay(Date.parse(since)) !== day) return invalid();
      }
      return {...d,totals_since:d.totals_since === null ? null : date(d.totals_since)};
    });
    return {observed_at,devices};
  });
  if (points.length && (!started || Date.parse(started) > Date.parse(points[0].observed_at))) return invalid();
  return {version:1,day,timezone:raw.timezone,interval_seconds:60,started_at:started,points};
}

export const HISTORY_WINDOW_MS = 24*60*60*1000;
export const USAGE_BUCKET_MS = 30*60*1000;
export const RECENT_LIVE_WINDOW_MS = 5*60*1000;
export const MAX_RECENT_LIVE_POINTS = 600;
const MAX_INTERVAL_MS = 90*1000;
const observedTime = point => Date.parse(point.observed_at);

function orderedPoints(history,now) {
  const byTime = new Map();
  for (const point of history?.points || []) {
    const time = observedTime(point);
    if (Number.isFinite(time) && time <= now) byTime.set(time,point);
  }
  return [...byTime].sort((a,b) => a[0]-b[0]).map(([,point]) => point);
}
export function availableDevices(history,snapshot,now=Date.now()) {
  const start=now-HISTORY_WINDOW_MS,names=new Map();
  for (const point of orderedPoints(history,now)) {
    if (observedTime(point)<start) continue;
    for (const d of point.devices) names.set(d.id,d.name);
  }
  const time=snapshot?.observed_at?Date.parse(snapshot.observed_at):NaN;
  if (time>=start && time<=now) for (const d of snapshot.devices) names.set(d.id,d.name);
  return [...names].map(([id,name]) => ({id,name}));
}
export function retainLivePoints(recent,snapshot,isFresh,now=Date.now()) {
  if (!Number.isFinite(now)) return invalid();
  const start=now-RECENT_LIVE_WINDOW_MS;
  const points=orderedPoints({points:recent},now).filter(point=>observedTime(point)>=start);
  const time=snapshot?.observed_at?Date.parse(snapshot.observed_at):NaN;
  if (isFresh && snapshot?.collector.state==='ok' && time>=start && time<=now) {
    // Retain real accepted observations, never extrapolated counters. Copy only
    // history fields so later renders cannot mutate a retained observation.
    points.push({observed_at:snapshot.observed_at,devices:snapshot.devices.map(d=>({
      id:d.id,name:d.name,upload_bytes:d.upload_bytes,download_bytes:d.download_bytes,
      counter_state:d.counter_state,counter_epoch:d.counter_epoch,totals_since:d.totals_since
    }))});
  }
  // This browser-only buffer spans asynchronous minute-history refreshes. Both
  // elapsed time and a hard point limit bound memory, including duplicate renders.
  return orderedPoints({points},now).slice(-MAX_RECENT_LIVE_POINTS);
}
export function historyWithLive(history,snapshot,isFresh,now=Date.now(),recent=[]) {
  const points=orderedPoints({points:[...(history?.points||[]),...recent]},now),start=now-HISTORY_WINDOW_MS;
  const time=snapshot?.observed_at?Date.parse(snapshot.observed_at):NaN;
  if (isFresh && snapshot?.collector.state==='ok' && time>=start && time<=now) {
    const last=points.at(-1),live={observed_at:snapshot.observed_at,devices:snapshot.devices};
    if (!last || time>observedTime(last)) points.push(live);
    else if (time===observedTime(last)) points[points.length-1]=live;
  }
  const first=points.findIndex(point=>observedTime(point)>=start);
  // Keep exactly one earlier sample. A straddling delta is still excluded below:
  // cumulative counters cannot tell how much of it was outside the window.
  return first<0?points.slice(-1):points.slice(Math.max(0,first-1));
}
function deviceDelta(before,after) {
  if (!before || !after || before.counter_state!=='partial' || after.counter_state!=='partial' ||
      !before.counter_epoch || before.counter_epoch!==after.counter_epoch ||
      !before.totals_since || before.totals_since!==after.totals_since ||
      [before.upload_bytes,before.download_bytes,after.upload_bytes,after.download_bytes].some(v=>v===null)) return null;
  const up=BigInt(after.upload_bytes)-BigInt(before.upload_bytes);
  const down=BigInt(after.download_bytes)-BigInt(before.download_bytes);
  return up<0n || down<0n?null:up+down;
}
function intervalDelta(before,after,id) {
  const old=new Map(before.devices.map(d=>[d.id,d])),current=new Map(after.devices.map(d=>[d.id,d]));
  if (id!==null) return deviceDelta(old.get(id),current.get(id));
  // A registration change leaves this interval unknown; never subtract totals
  // across different rosters or silently supply zero for a missing device.
  if (!old.size || old.size!==current.size || [...old.keys()].some(key=>!current.has(key))) return null;
  let sum=0n;
  for (const [key,d] of old) {
    const delta=deviceDelta(d,current.get(key));
    if (delta===null)return null;
    sum+=delta;
  }
  return sum;
}
export function chartSeries(points,selection,devices,now=Date.now()) {
  if (!Number.isFinite(now)) return invalid();
  const windowStart=now-HISTORY_WINDOW_MS,alignedStart=Math.floor(windowStart/USAGE_BUCKET_MS)*USAGE_BUCKET_MS;
  const specs=selection.mode==='all'?[{id:'all',name:'全部设备',deviceId:null}]:selection.ids.map(id=>({id,name:devices.find(d=>d.id===id)?.name||id,deviceId:id}));
  return specs.map(spec=>{
    const buckets=[];
    for(let start=alignedStart;start<now;start+=USAGE_BUCKET_MS) {
      const end=Math.min(start+USAGE_BUCKET_MS,now);
      buckets.push({time:end,start:Math.max(start,windowStart),end,bytes:null,partial:true,coverage:[]});
    }
    for(let i=1;i<points.length;i++) {
      const before=points[i-1],after=points[i],start=observedTime(before),end=observedTime(after);
      if (!Number.isFinite(start) || !Number.isFinite(end) || start<windowStart || end>now || end<=start || end-start>MAX_INTERVAL_MS) continue;
      const delta=intervalDelta(before,after,spec.deviceId);
      if(delta===null)continue;
      // Right-closed UTC buckets (start,end]: an observation exactly at 10:30
      // belongs to 10:00–10:30. Do not interpolate or prorate interval bytes.
      const index=Math.floor((end-1-alignedStart)/USAGE_BUCKET_MS),bucket=buckets[index];
      if(!bucket)continue;
      bucket.bytes=(bucket.bytes??0n)+delta;
      // Coverage marks missing intervals independently of end-time attribution.
      const first=Math.floor((start-alignedStart)/USAGE_BUCKET_MS);
      for(let j=first;j<=index;j++) {
        const b=buckets[j],a=Math.max(start,b.start),z=Math.min(end,b.end);
        if(z>a)b.coverage.push([a,z]);
      }
    }
    const segments=[];let segment=null;
    for(const bucket of buckets) {
      let covered=0,through=bucket.start;
      for(const [start,end] of bucket.coverage) {
        covered+=Math.max(0,end-Math.max(start,through));through=Math.max(through,end);
      }
      bucket.partial=bucket.bytes===null || bucket.end-bucket.start<USAGE_BUCKET_MS || covered<bucket.end-bucket.start;
      delete bucket.coverage;
      if(bucket.bytes===null){segment=null;continue;}
      if(!segment){segment=[];segments.push(segment);}
      segment.push(bucket);
    }
    const last=buckets.at(-1);
    return {id:spec.id,name:spec.name,buckets,segments,last:last?.bytes!==null?last:null};
  });
}
