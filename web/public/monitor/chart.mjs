import {formatBytes,malaysiaTime} from './model.mjs';
import {allDevices,selectDevice,availableDevices,retainLivePoints,historyWithLive,chartSeries} from './history-model.mjs';

const $ = id => document.getElementById(id);
const NS = 'http://www.w3.org/2000/svg';
const el = (tag,attrs={},value) => {
  const node=document.createElementNS(NS,tag);
  for (const [key,v] of Object.entries(attrs)) node.setAttribute(key,String(v));
  if (value !== undefined) node.textContent=value;
  return node;
};
const quantity = value => {const q=formatBytes(value);return `${q.value}${q.value === '—' ? '' : ` ${q.unit}`}`;};
const timeLabel = timestamp => new Date(timestamp).toLocaleString('zh-CN',{timeZone:'Asia/Kuala_Lumpur',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false});
let selection=allDevices(),inputs=null,controlsKey='';
let recentLive=[];
let measuredWidth=0;
if (typeof ResizeObserver !== 'undefined') new ResizeObserver(entries=>{
  const width=Math.round(entries[0].contentRect.width);
  if(width!==measuredWidth){measuredWidth=width;if(inputs)renderHistoryChart(inputs);}
}).observe($('chart-svg').parentElement);
else window.addEventListener('resize',()=>{if(inputs)renderHistoryChart(inputs);});
$('chart-all').addEventListener('click',() => {selection=allDevices();if(inputs)renderHistoryChart(inputs);});
$('chart-devices').addEventListener('change',event => {
  const checkbox=event.target;
  if (!(checkbox instanceof HTMLInputElement) || !checkbox.dataset.device) return;
  selection=selectDevice(selection,checkbox.dataset.device,checkbox.checked);
  if(inputs)renderHistoryChart(inputs);
});

function controls(devices) {
  $('chart-all').setAttribute('aria-pressed',String(selection.mode==='all'));
  const key=JSON.stringify([devices,selection]);
  if (key===controlsKey)return;
  controlsKey=key;
  // Keep the focused checkbox stable while updating the selection styling.
  const nodes=new Map([...$('chart-devices').children].map(label=>[label.firstElementChild.dataset.device,label]));
  for (const d of devices) {
    let label=nodes.get(d.id);
    if (!label) {
      label=document.createElement('label');label.className='device-choice';
      const input=document.createElement('input');input.type='checkbox';input.dataset.device=d.id;
      const span=document.createElement('span');label.append(input,span);$('chart-devices').append(label);
    }
    label.firstElementChild.checked=selection.mode==='selected'&&selection.ids.includes(d.id);
    label.lastElementChild.textContent=d.name;
    nodes.delete(d.id);
  }
  for (const node of nodes.values())node.remove();
}
export function renderHistoryChart(nextInputs) {
  inputs=nextInputs;
  const {history,snapshot,isFresh,historyState,now=Date.now()}=inputs;
  recentLive=retainLivePoints(recentLive,snapshot,isFresh,now);
  const points=historyWithLive(history,snapshot,isFresh,now,recentLive);
  const devices=availableDevices({points},snapshot,now);
  controls(devices);
  const series=chartSeries(points,selection,devices,now);
  const values=series.flatMap(s=>s.segments.flat());
  const emptySelection=selection.mode==='selected'&&selection.ids.length===0;
  $('chart-period').textContent='每 30 分钟用量 · 上传 + 下载';
  const notes=[];
  if (historyState==='error')notes.push('历史更新中断，保留已读取记录');
  else if(historyState==='loading'&&!history)notes.push('正在读取历史');
  if (!isFresh && snapshot)notes.push('实时更新暂不可用');
  if (points.length) notes.push(`最近采样 ${malaysiaTime(points.at(-1).observed_at)}`);
  $('chart-status').textContent=notes.join(' · ') || '从开始记录后显示';
  $('chart-empty').hidden=Boolean(values.length)&&!emptySelection;
  $('chart-svg').toggleAttribute('hidden',!values.length||emptySelection);
  $('chart-legend').replaceChildren();
  if (emptySelection) {
    $('chart-empty-title').textContent='选择要查看的设备';
    $('chart-empty-detail').textContent='勾选一台或多台设备，或点击「全部设备」查看总览。';
  } else if (!values.length) {
    $('chart-empty-title').textContent=historyState==='error'?'暂时无法读取流量走势':'等待时段用量';
    $('chart-empty-detail').textContent='收到连续采样后显示各时段用量；没有记录的时段留空。';
  }
  for (let i=0;i<series.length;i++) {
    const item=document.createElement('li');item.className=`chart-key color-${i%8}`;
    const dot=document.createElement('span');dot.className='chart-key-dot';dot.setAttribute('aria-hidden','true');
    const name=document.createElement('span');name.textContent=series[i].name;
    const value=document.createElement('strong');value.textContent=`本时段 ${quantity(series[i].last?.bytes ?? null)}`;
    item.append(dot,name,value);$('chart-legend').append(item);
  }
  if (!values.length||emptySelection) {$('chart-summary').textContent=$('chart-empty-detail').textContent;return;}
  const svg=$('chart-svg'),width=Math.max(280,Math.round(svg.getBoundingClientRect().width)),height=width<600?260:300,right=20,top=20,bottom=54;
  const start=now-86400000,end=now;
  const max=Math.max(...values.map(v=>Number(v.bytes)),0);
  const magnitude=10**Math.floor(Math.log10(Math.max(max,1)));
  const ceiling=max===0?1000000:Math.max(4,([1,2,5,10].find(n=>n*magnitude>=max)||10)*magnitude);
  const left=Math.max(58,Math.min(100,quantity(BigInt(Math.round(ceiling))).length*7+16));
  svg.setAttribute('viewBox',`0 0 ${width} ${height}`);
  svg.setAttribute('height',String(height));
  const x=t=>left+(t-start)/(end-start)*(width-left-right),y=b=>top+(1-Number(b)/ceiling)*(height-top-bottom);
  const children=[el('title',{id:'usage-chart-title'},'近24小时流量走势'),el('desc',{id:'usage-chart-description'},'横轴固定显示最近24小时的马来西亚时间，纵轴为每30分钟上传与下载的用量。没有记录的时段留空。')];
  for(let i=0;i<=4;i++) {
    const amount=ceiling*i/4,at=y(amount);
    children.push(el('line',{x1:left,x2:width-right,y1:at,y2:at,class:'chart-grid'}),el('text',{x:left-12,y:at+4,'text-anchor':'end',class:'chart-axis'},quantity(BigInt(Math.round(amount)))));
  }
  const timeTicks=width<600?2:4;
  for(let i=0;i<=timeTicks;i++) {
    const t=start+(end-start)*i/timeTicks;
    children.push(el('text',{x:x(t),y:height-bottom+26,'text-anchor':i===0?'start':i===timeTicks?'end':'middle',class:'chart-axis'},timeLabel(t)));
  }
  children.push(el('text',{x:left,y:height-4,class:'chart-axis chart-axis-caption'},'时间（马来西亚）'),el('text',{x:width-right,y:height-4,'text-anchor':'end',class:'chart-axis chart-axis-caption'},'用量 / 30 分钟'));
  for(let i=0;i<series.length;i++) for(const segment of series[i].segments) {
    const d=segment.map((point,j)=>`${j?'L':'M'}${x(point.time).toFixed(2)},${y(point.bytes).toFixed(2)}`).join(' ');
    children.push(el('path',{d,class:`chart-line color-${i%8}`,...(i>=8?{'stroke-dasharray':'7 4'}:{})}));
    for (const point of segment) {
      const circle=el('circle',{cx:x(point.time),cy:y(point.bytes),r:2.5,class:`chart-point color-${i%8}`});
      circle.append(el('title',{},`${series[i].name} · ${timeLabel(point.start)}–${malaysiaTime(new Date(point.end).toISOString())} · ${quantity(point.bytes)}${point.partial?'（已记录部分）':''}`));children.push(circle);
    }
  }
  svg.replaceChildren(...children);
  $('chart-summary').textContent=series.map(s=>`${s.name}：${s.last?`本时段已记录 ${quantity(s.last.bytes)}`:'本时段用量未知'}`).join('；');
}
