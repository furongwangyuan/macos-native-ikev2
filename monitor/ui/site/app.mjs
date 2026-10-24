import {normalizeSnapshot,freshness,aggregate,formatRate,formatBytes,formatDuration,isLoopbackLocation,dailyContext,malaysiaTime,POLL_MS,REQUEST_TIMEOUT_MS} from './model.mjs';

const $ = id => document.getElementById(id);
const set = (id,value) => { $(id).textContent=value; };
const state = {snapshot:null,interrupted:false,busy:false,allowed:isLoopbackLocation(window.location)};
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
  $('notice').classList.toggle('warning',['stale','interrupted','clock_error'].includes(status));
  const messages={
    fresh:['本机数据已更新','每 2 秒读取一次；速度为采样窗口内的平均值。'],
    interrupted:['更新暂时中断','下方保留上次记录，暂不代表当前连接与速度。'],
    stale:['数据已过期','超过 10 秒未取得新观察；下方仅为上次记录。'],
    clock_error:['观察时间异常','本机与采集器时间不一致，下方记录暂不可作为实时状态。'],
    unavailable:retained?['采集暂时不可用','下方保留上次记录的日期与已采样小计；当前连接、时长和速度均待确认。']:['监控数据不可用','暂时无法确认 VPN 服务或设备状态，未知数值不会显示成零。']
  };
  const message=state.allowed?messages[status]:['尚未连接本机监控','请从这台 Mac 的本机监控入口打开；此页面不会连接外部服务。'];
  set('notice-title',message[0]);set('notice-detail',message[1]);
  const server=current?snapshot.server.state:'unknown';
  const badge=$('server-state');badge.replaceChildren(newElement('span','status-dot'),document.createTextNode(({running:'VPN 服务运行中',stopped:'VPN 服务已停止',unknown:current?'服务状态未知':'状态待确认'})[server]));
  badge.className=`status-pill ${server==='running'?'online':server==='stopped'?'offline':'neutral'}`;
  set('last-update',snapshot?.observed_at?`${current?'更新于':'上次观察'} ${niceTime(snapshot.observed_at)}`:'尚无有效观察');
  $('refresh').disabled=!state.allowed||state.busy;
  if(!snapshot || (snapshot.collector.state!=='ok' && !retained)){
    set('online-value','—');set('online-detail','等待连接状态');showQuantity('download',formatRate(null));showQuantity('upload',formatRate(null));showQuantity('total',formatBytes(null));
    set('total-detail','尚无有效的当日采样');set('device-count','等待数据');$('device-table').hidden=true;$('empty-state').hidden=false;
    set('empty-title','等待设备数据');set('empty-detail','接入本机监控后，已登记的家庭设备会显示在这里。');
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

async function refresh() {
  if(!state.allowed||state.busy)return;
  state.busy=true;render();
  const abort=new AbortController(), timeout=setTimeout(()=>abort.abort(),REQUEST_TIMEOUT_MS);
  try {
    const response=await fetch('/api/status',{method:'GET',cache:'no-store',credentials:'omit',redirect:'error',signal:abort.signal,headers:{Accept:'application/json'}});
    if(!response.ok||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||''))throw new Error('invalid_response');
    const length=response.headers.get('content-length');if(length && Number(length)>131072)throw new Error('oversized_response');
    if(!response.body)throw new Error('missing_body');
    const reader=response.body.getReader(),chunks=[];let bytes=0;
    while(true){const result=await reader.read();if(result.done)break;bytes+=result.value.byteLength;if(bytes>131072){await reader.cancel();throw new Error('oversized_response');}chunks.push(result.value);}
    const joined=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){joined.set(chunk,offset);offset+=chunk.byteLength;}
    const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(joined));
    state.snapshot=normalizeSnapshot(parsed);state.interrupted=false;
  } catch {
    state.interrupted=true;
  } finally {
    clearTimeout(timeout);state.busy=false;render();
  }
}

$('refresh').addEventListener('click',refresh);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
render();refresh();
setInterval(()=>{if(document.hidden)return;render();refresh();},POLL_MS);
