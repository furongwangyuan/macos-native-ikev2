import {normalizeSnapshot,freshness,aggregate,formatRate,formatBytes,formatDuration,dailyContext,malaysiaTime,malaysiaDay,POLL_MS,REQUEST_TIMEOUT_MS} from './model.mjs';

import {normalizeHistory,HISTORY_POLL_MS} from './history-model.mjs';
import {renderHistoryChart} from './chart.mjs';

const $ = id => document.getElementById(id);
const set = (id,value) => { $(id).textContent=value; };
const state = {snapshot:null,interrupted:false,busy:false,allowed:true,history:null,historyDay:null,historyState:'loading',historyBusy:false,historyRequestedAt:0};
const newElement = (tag,className,value) => {
  const el=document.createElement(tag);
  if(className)el.className=className;
  if(value!==undefined)el.textContent=value;
  return el;
};
const niceTime = malaysiaTime;
const showQuantity = (id,value) => {set(`${id}-value`,value.value);set(`${id}-unit`,value.unit);};
const metricText = (formatter,value) => {const f=formatter(value);return `${f.value}${f.value==='—'?'':` ${f.unit}`}`;};

function deviceRow(device,snapshot,isCurrent,dayView) {
  const row=newElement('tr');
  const cell=(label)=>{const el=newElement('td');el.dataset.label=label;row.append(el);return el;};
  const identity=newElement('div','device-identity');
  identity.append(newElement('span','device-avatar'));
  const label=newElement('div');label.append(newElement('p','device-name',device.name));
  label.append(newElement('p','row-note',({enabled:'已登记的家庭设备',disabled:'登记已停用',revoked:'登记已撤销'})[device.registration_state]));identity.append(label);cell('设备').append(identity);
  const names={online:isCurrent?'已连接':'上次在线',offline:isCurrent?'未连接':'上次未连接',unknown:'状态未知'};
  cell('状态').append(newElement('span',`row-status ${device.state==='online'?'':device.state}`,names[device.state]));
  cell('已连接').textContent=device.state==='online'?formatDuration(device.connected_since,snapshot.observed_at):'—';
  const rates=cell('下载 / 上传');
  for(const [arrow,value] of [['↓',device.download_bps],['↑',device.upload_bps]]){
    const line=newElement('div','row-rate');line.append(newElement('span','arrow',arrow),newElement('span','',metricText(formatRate,value)));rates.append(line);
  }
  rates.append(newElement('p','row-note',device.rate_window_ms===null?'测速窗口未知':`最近 ${Number((device.rate_window_ms/1000).toFixed(1))} 秒平均`));
  const usage=cell(dayView.column);
  const total=device.counter_state==='partial'?BigInt(device.upload_bytes)+BigInt(device.download_bytes):null;
  usage.append(newElement('p','',metricText(formatBytes,total)));
  if(device.counter_state==='partial'){
    usage.append(newElement('p','row-note',`↓ ${metricText(formatBytes,device.download_bytes)} · ↑ ${metricText(formatBytes,device.upload_bytes)}`));
    usage.append(newElement('p','row-note',`自 ${malaysiaTime(device.totals_since)} 起 · 可能遗漏`));
  }
  else usage.append(newElement('p','row-note','等待该日有效采样区间'));
  return row;
}

function render() {
  const received=state.snapshot;
  const retained=Boolean(received && received.collector.state==='unavailable' && received.observed_at && received.devices.length);
  // Persisted subtotals remain useful during a sampling interruption. None of
  // the retained connection/rate fields may appear to be current observations.
  const snapshot=retained?{...received,devices:received.devices.map(d=>({...d,state:'unknown',connected_since:null,upload_bps:null,download_bps:null,rate_window_ms:null}))}:received;
  const status=freshness(snapshot,Date.now(),state.interrupted);
  const current=status==='fresh';
  const dayView=dailyContext(snapshot);
  set('total-label',dayView.label);set('usage-column',dayView.column);
  set('coverage-note',`数据来源：VPN 隧道计数 · ${dayView.period}`);
  set('coverage-sampling',dayView.sampling);
  document.body.classList.toggle('stale',Boolean(snapshot)&&!current);
  const server=current?snapshot.server.state:'unknown';
  const badge=$('server-state');badge.replaceChildren(newElement('span','status-dot'),document.createTextNode(({running:'VPN 服务运行中',stopped:'VPN 服务已停止',unknown:current?'服务状态未知':'状态待确认'})[server]));
  badge.className=`status-pill ${server==='running'?'online':server==='stopped'?'offline':'neutral'}`;
  const messages={fresh:'更新于',interrupted:'更新中断 · 上次观察',stale:'数据已过期 · 上次观察',clock_error:'观察时间异常 · 上次观察',unavailable:retained?'采集不可用 · 上次观察':'监控数据暂不可用'};
  set('last-update',`${messages[status]}${snapshot?.observed_at?` ${niceTime(snapshot.observed_at)}`:''}${state.historyState==='error'?' · 历史暂未更新':''}`);
  renderHistoryChart({history:state.history,snapshot:received,isFresh:current,historyState:state.historyState});
  if(!snapshot || (snapshot.collector.state!=='ok' && !retained)){
    set('online-value','—');set('online-detail','等待连接状态');showQuantity('download',formatRate(null));showQuantity('upload',formatRate(null));showQuantity('total',formatBytes(null));
    set('total-detail','尚无有效的当日采样');set('device-count','等待数据');$('device-table').hidden=true;$('empty-state').hidden=false;
    set('empty-title','等待设备数据');set('empty-detail','收到 Mac 同步的数据后，已登记的家庭设备会显示在这里。');
    if(snapshot)set('coverage-limitation',snapshot.coverage.limitation);
    return;
  }
  const totals=aggregate(snapshot);
  set('online-value',totals.online===null?'—':String(totals.online));
  set('online-detail',totals.online===null?'部分设备状态待确认':`共 ${snapshot.devices.length} 台已登记设备${current?'':' · 上次记录'}`);
  showQuantity('download',formatRate(totals.download_bps));showQuantity('upload',formatRate(totals.upload_bps));showQuantity('total',formatBytes(totals.total_bytes));
  const reasons={mixed_epochs:'统计代际不同，暂不合并',partial:'当日已采样小计 · 可能遗漏',missing:'当日采样尚不完整'};
  set('total-detail',reasons[totals.total_reason]);set('device-count',`${snapshot.devices.length} 台设备`);
  set('coverage-limitation',snapshot.coverage.limitation);
  $('device-rows').replaceChildren(...snapshot.devices.map(d=>deviceRow(d,snapshot,current,dayView)));
  const empty=snapshot.devices.length===0;$('device-table').hidden=empty;$('empty-state').hidden=!empty;
  set('empty-title','尚无已登记设备');set('empty-detail','采集器没有返回设备记录；这不代表流量指标已测得为零。');
}

async function readJSON(url,limit,signal) {
  const response=await fetch(url,{method:'GET',cache:'no-store',credentials:'same-origin',redirect:'error',signal,headers:{Accept:'application/json'}});
  if(!response.ok||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))throw new Error('invalid_response');
  const length=response.headers.get('content-length');if(length && Number(length)>limit)throw new Error('oversized_response');
  if(!response.body)throw new Error('missing_body');
  const reader=response.body.getReader(),chunks=[];let bytes=0;
  while(true){const result=await reader.read();if(result.done)break;bytes+=result.value.byteLength;if(bytes>limit){await reader.cancel();throw new Error('oversized_response');}chunks.push(result.value);}
  const joined=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){joined.set(chunk,offset);offset+=chunk.byteLength;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(joined));
}
async function refresh() {
  if(!state.allowed||state.busy)return;
  state.busy=true;
  const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),REQUEST_TIMEOUT_MS);
  try {
    state.snapshot=normalizeSnapshot(await readJSON('/api/status',131072,abort.signal));state.interrupted=false;
  } catch {state.interrupted=true;}
  finally {clearTimeout(timeout);state.busy=false;render();}
}
async function refreshHistory() {
  if(!state.allowed||state.historyBusy)return;
  const day=malaysiaDay();
  const days=[malaysiaDay(Date.now()-86400000),day];
  state.historyBusy=true;state.historyDay=day;state.historyRequestedAt=Date.now();
  if(!state.history)state.historyState='loading';
  const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),15000);
  try {
    const daily=await Promise.all(days.map(async date=>normalizeHistory(await readJSON(`/api/history?day=${date}`,8*1024*1024,abort.signal),date)));
    const history={days,points:daily.flatMap(item=>item.points)};
    if(day===malaysiaDay()) {state.history=history;state.historyState='ready';}
  } catch {if(day===malaysiaDay())state.historyState='error';}
  finally {clearTimeout(timeout);state.historyBusy=false;render();}
}
document.addEventListener('visibilitychange',()=>{
  if(document.hidden)return;
  refresh();
  if(state.historyDay!==malaysiaDay()||Date.now()-state.historyRequestedAt>=HISTORY_POLL_MS)refreshHistory();
});
render();refresh();refreshHistory();
setInterval(()=>{
  if(document.hidden)return;
  // Successful polls render once on completion. While a request is pending
  // (or polling disabled), keep aging the retained snapshot every second.
  if(state.busy||!state.allowed)render();else refresh();
  if(state.historyDay!==malaysiaDay())refreshHistory();
},POLL_MS);
setInterval(()=>{if(!document.hidden)refreshHistory();},HISTORY_POLL_MS);
