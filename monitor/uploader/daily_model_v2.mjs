export const STALE_AFTER_MS = 10000;
export const POLL_MS = 2000;
export const REQUEST_TIMEOUT_MS = 1500;
const states = (...values) => value => values.includes(value);
const bad = () => { throw new TypeError('invalid_status_contract'); };
const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : bad();
const oneOf = (value, values) => values.includes(value) ? value : bad();
const nullableDate = value => {
  if (value === null) return null;
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0,19) !== value.slice(0,19)) return bad();
  return value;
};
const text = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value) ? value : bad();
const nullableText = (value, max) => value === null ? null : text(value, max);
const rate = value => value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1e15) ? value : bad();
const byteString = value => value === null || (typeof value === 'string' && /^(0|[1-9][0-9]{0,29})$/.test(value)) ? value : bad();

export const DAILY_TIMEZONE = 'Asia/Kuala_Lumpur';
const calendarDay = value => {
  if (value === null) return null;
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\d$/.test(value)) return bad();
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString().slice(0,10)!==value) return bad();
  return value;
};
const withinDay = (value, period) => period.day_started_at !== null && Date.parse(value)>=Date.parse(period.day_started_at) && Date.parse(value)<Date.parse(period.day_started_at)+86400000;
export function malaysiaDay(timestamp = Date.now()) {
  if (!Number.isFinite(timestamp)) return null;
  const parts = new Intl.DateTimeFormat('en-CA',{timeZone:DAILY_TIMEZONE,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(timestamp));
  const take = name => parts.find(p=>p.type===name).value;
  return `${take('year')}-${take('month')}-${take('day')}`;
}
export function malaysiaTime(value) {
  return value ? new Date(value).toLocaleTimeString('zh-CN',{timeZone:DAILY_TIMEZONE,hour12:false}) : '—';
}
export function dailyContext(snapshot, now = Date.now()) {
  const period = snapshot?.coverage;
  const day = period?.day;
  if (!day) return {label:'今日累计流量',column:'今日流量',period:'统计日期待确认',sampling:'今日尚无有效采样',isToday:false};
  const isToday = day===malaysiaDay(now);
  return {
    label:isToday?'今日累计流量':`${day} 已采样流量`,
    column:isToday?'今日流量':`${day.slice(5)} 流量`,
    period:`${day} 00:00–24:00 · 马来西亚时间`,
    sampling:period.observed_since?`自 ${malaysiaTime(period.observed_since)} 开始观察 · 可能遗漏`:'该日尚无有效采样',
    isToday
  };
}

export function normalizeSnapshot(input) {
  const raw = obj(input);
  if (raw.schema_version !== 2) return bad();
  const collector = obj(raw.collector), server = obj(raw.server), coverage = obj(raw.coverage);
  const snapshot = {
    schema_version: 2,
    observed_at: nullableDate(raw.observed_at),
    collector: {state: oneOf(collector.state, ['ok','unavailable']), started_at: nullableDate(collector.started_at)},
    server: {state: oneOf(server.state, ['running','stopped','unknown'])},
    coverage: {kind: oneOf(coverage.kind, ['ipsec_child_counters']), totals_scope: oneOf(coverage.totals_scope, ['calendar_day']), timezone: oneOf(coverage.timezone, ['Asia/Kuala_Lumpur']), day: calendarDay(coverage.day), day_started_at: nullableDate(coverage.day_started_at), observed_since: nullableDate(coverage.observed_since), limitation: text(coverage.limitation,600)},
    devices: []
  };
  if (snapshot.collector.state === 'ok' && (!snapshot.observed_at || !snapshot.coverage.day)) return bad();
  const period = snapshot.coverage;
  if (period.day === null) {
    if (period.day_started_at !== null || period.observed_since !== null) return bad();
  } else {
    if (period.day_started_at === null || Date.parse(period.day_started_at) !== Date.parse(`${period.day}T00:00:00Z`) - 8*3600000) return bad();
    if (snapshot.observed_at && malaysiaDay(Date.parse(snapshot.observed_at)) !== period.day) return bad();
    if (period.observed_since && (!withinDay(period.observed_since, period) || (snapshot.observed_at && Date.parse(period.observed_since)>Date.parse(snapshot.observed_at)))) return bad();
  }
  if (!Array.isArray(raw.devices) || raw.devices.length > 100) return bad();
  const ids = new Set();
  snapshot.devices = raw.devices.map(item => {
    const d = obj(item);
    if (typeof d.id !== 'string' || !/^[a-zA-Z0-9_-]{1,48}$/.test(d.id) || ids.has(d.id)) return bad();
    ids.add(d.id);
    const window = d.rate_window_ms;
    if (window !== null && (!Number.isSafeInteger(window) || window <= 0 || window > 3600000)) return bad();
    const device = {
      id: d.id, name: text(d.name,80), state: oneOf(d.state, ['online','offline','unknown']),
      connected_since: nullableDate(d.connected_since), rate_window_ms: window,
      upload_bps: rate(d.upload_bps), download_bps: rate(d.download_bps),
      upload_bytes: byteString(d.upload_bytes), download_bytes: byteString(d.download_bytes),
      totals_since: nullableDate(d.totals_since), counter_epoch: nullableText(d.counter_epoch,80),
      counter_state: oneOf(d.counter_state, ['partial','unavailable'])
    };
    if ((device.upload_bps !== null || device.download_bps !== null) && window === null) return bad();
    if (device.counter_state === 'partial' && [device.upload_bytes,device.download_bytes,device.totals_since,device.counter_epoch].some(v=>v===null)) return bad();
    if (device.totals_since && (!withinDay(device.totals_since, period) || (snapshot.observed_at && Date.parse(device.totals_since)>Date.parse(snapshot.observed_at)))) return bad();
    if (device.counter_state === 'partial' && period.observed_since === null) return bad();
    if (device.state === 'online' && snapshot.server.state === 'stopped') return bad();
    if (device.connected_since && snapshot.observed_at && Date.parse(device.connected_since) > Date.parse(snapshot.observed_at)) return bad();
    return device;
  });
  return snapshot;
}

export function freshness(snapshot, now = Date.now(), interrupted = false) {
  if (!snapshot || snapshot.collector.state !== 'ok' || !snapshot.observed_at) return 'unavailable';
  const age = now - Date.parse(snapshot.observed_at);
  if (age < -5000) return 'clock_error';
  if (age > STALE_AFTER_MS) return 'stale';
  return interrupted ? 'interrupted' : 'fresh';
}

export function aggregate(snapshot) {
  const devices = snapshot.devices;
  // Rates cover known-online devices in this snapshot. Verified offline devices
  // add no current traffic, without inventing a per-device sampling window.
  const active = devices.filter(d=>d.state==='online');
  const sumRates = key => devices.length && !devices.some(d=>d.state==='unknown') && active.every(d=>d[key]!==null) ? active.reduce((sum,d)=>sum+d[key],0) : null;
  const online = devices.some(d=>d.state==='unknown') ? null : devices.filter(d=>d.state==='online').length;
  let total = null, totalReason = 'missing';
  if (devices.length && devices.every(d=>d.counter_state==='partial')) {
    const first = devices[0];
    if (devices.every(d=>d.counter_epoch===first.counter_epoch)) {
      total = devices.reduce((sum,d)=>sum+BigInt(d.upload_bytes)+BigInt(d.download_bytes),0n);
      totalReason = 'partial';
    } else totalReason = 'mixed_epochs';
  }
  return {online, upload_bps:sumRates('upload_bps'), download_bps:sumRates('download_bps'), total_bytes:total, total_reason:totalReason};
}

function decimal(value, digits) {
  return new Intl.NumberFormat('zh-CN',{minimumFractionDigits:0,maximumFractionDigits:digits}).format(value);
}
export function formatRate(value) {
  if (value === null) return {value:'—',unit:'Mbps'};
  const divisor = value >= 1e9 ? 1e9 : 1e6;
  return {value:decimal(value/divisor,value>0&&value<1e6?3:2),unit:divisor===1e9?'Gbps':'Mbps'};
}
export function formatBytes(value) {
  if (value === null) return {value:'—',unit:'GB'};
  const count = BigInt(value);
  const units = ['B','KB','MB','GB','TB','PB','EB','ZB','YB'];
  let index=0, divisor=1n;
  while(index<units.length-1 && count >= divisor*1000n){divisor*=1000n;index++;}
  const hundredths = (count*100n + divisor/2n)/divisor;
  return {value:decimal(Number(hundredths)/100,2),unit:units[index]};
}
export function formatDuration(start, observed) {
  if (!start || !observed) return '—';
  const seconds = Math.floor((Date.parse(observed)-Date.parse(start))/1000);
  if (!Number.isFinite(seconds) || seconds<0) return '—';
  const days=Math.floor(seconds/86400), hours=Math.floor(seconds/3600)%24, minutes=Math.floor(seconds/60)%60;
  return `${days?`${days}天 `:''}${String(hours).padStart(2,'0')}:${String(minutes).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`;
}
export function isLoopbackLocation(location) {
  return ['http:','https:'].includes(location.protocol) && ['127.0.0.1','localhost','[::1]','::1'].includes(location.hostname);
}
