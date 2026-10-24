/** Serial ordinary-user telemetry loop. Fixed source, Site and Keychain item. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {normalizeSnapshot} from './model.mjs';

export const CONFIGURED=false;
export const STATUS='/private/var/run/family-vpn-monitor/status.json';
export const URL='https://vpn-monitor.example.invalid/api/telemetry';
export const ACCOUNT='appgprj_REPLACE_WITH_YOUR_PRIVATE_SITE';
export const SERVICE='org.familyvpn.sites.monitor';
export const CODES=['uploaded','public_unavailable','schema_rejected','keychain_unavailable','access_denied','upload_timeout','remote_rejected','network_failed'];
const LIMIT=131072;
const stamp=s=>[s.dev,s.ino,s.mode,s.uid,s.gid,s.nlink,s.size,s.mtimeNs,s.ctimeNs].map(String).join(':');
export const installedDirectory=()=>path.join(os.homedir(),'Library','Application Support','Family VPN','Sites');

// Internal file primitive is parameterized only for ordinary temporary-file tests.
// The executable entry always calls this with STATUS and uid 0.
export function readStatusFile(filename=STATUS, expectedUid=0) {
  const parent=path.dirname(filename), ds=fs.lstatSync(parent,{bigint:true});
  if (!ds.isDirectory()||ds.isSymbolicLink()||ds.uid!==BigInt(expectedUid)||(ds.mode&0o777n)!==0o755n) throw Error('public_unavailable');
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {
    const before=fs.fstatSync(fd,{bigint:true});
    if (!before.isFile()||before.uid!==BigInt(expectedUid)||before.nlink!==1n||(before.mode&0o777n)!==0o644n||before.size>BigInt(LIMIT)) throw Error('public_unavailable');
    const buffer=Buffer.alloc(LIMIT+1);let used=0;
    while(used<buffer.length){const n=fs.readSync(fd,buffer,used,buffer.length-used,null);if(!n)break;used+=n;}
    const after=fs.fstatSync(fd,{bigint:true}), named=fs.lstatSync(filename,{bigint:true}), nowDir=fs.lstatSync(parent,{bigint:true});
    if (used>LIMIT||BigInt(used)!==before.size||stamp(before)!==stamp(after)||stamp(before)!==stamp(named)||
        [ds.dev,ds.ino,ds.uid,ds.mode].join(':')!==[nowDir.dev,nowDir.ino,nowDir.uid,nowDir.mode].join(':')) throw Error('public_unavailable');
    return buffer.subarray(0,used);
  } finally {fs.closeSync(fd);}
}
export function normalizedBody(raw) {
  if (!Buffer.isBuffer(raw)||raw.length>LIMIT) throw Error('schema_rejected');
  const value=normalizeSnapshot(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)));
  const body=JSON.stringify(value);
  if (Buffer.byteLength(body)>LIMIT) throw Error('schema_rejected');
  return body;
}
export function keychainToken(run=spawnSync) {
  const result=run('/usr/bin/security',['find-generic-password','-s',SERVICE,'-a',ACCOUNT,'-w'],
    {stdio:['ignore','pipe','pipe'],timeout:5000,maxBuffer:32768,encoding:'utf8',env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin',LANG:'C',LC_ALL:'C'}});
  if (result.error||result.status!==0||typeof result.stdout!=='string') throw Error('keychain_unavailable');
  const token=result.stdout.replace(/\r?\n$/,'');
  if (!/^[\x21-\x7e]{1,16384}$/.test(token)) throw Error('keychain_unavailable');
  return token;
}
export async function once({read=readStatusFile, token=keychainToken, send=fetch, now=()=>new Date().toISOString(), signal}={}) {
  let body,credential,code;
  try{body=normalizedBody(read());}catch(error){code=error?.message==='schema_rejected'||error instanceof SyntaxError||error instanceof TypeError?'schema_rejected':'public_unavailable';}
  if(!code){try{credential=token();}catch{code='keychain_unavailable';}}
  if(!code){
    const stop=new AbortController(), timer=setTimeout(()=>stop.abort(),10000);
    const abort=()=>stop.abort();
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
    try {
      const response=await send(URL,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json',
        'OAI-Sites-Authorization':'Bearer '+credential},body,redirect:'error',signal:stop.signal});
      code=response.status>=200&&response.status<300?'uploaded':[401,403].includes(response.status)?'access_denied':'remote_rejected';
      // Never read, print or store the remote response body (including error text).
      if(response.body) await response.body.cancel();
    } catch {code=stop.signal.aborted?'upload_timeout':'network_failed';}
    finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);credential=undefined;}
  }
  return {event:'sites_telemetry_upload',code,time:now()};
}
function statusShape(value){
  return value&&Object.keys(value).sort().join(',')==='code,event,time'&&value.event==='sites_telemetry_upload'&&
    CODES.includes(value.code)&&typeof value.time==='string'&&Number.isFinite(Date.parse(value.time));
}
export function writeStatus(directory,value) {
  if(!statusShape(value))throw Error('status_contract');
  const before=fs.lstatSync(directory);if(!before.isDirectory()||before.isSymbolicLink()||before.uid!==process.getuid()||(before.mode&0o777)!==0o700)throw Error('status_directory');
  const final=path.join(directory,'upload-status.json');
  try {
    const s=fs.lstatSync(final);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.size>1024)throw Error('status_existing');
    if(!statusShape(JSON.parse(fs.readFileSync(final))))throw Error('status_existing');
  } catch(e){if(e.code!=='ENOENT')throw e;}
  const temp=path.join(directory,'.upload-status-'+crypto.randomUUID());let fd;
  try{fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fchmodSync(fd,0o600);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    const current=fs.lstatSync(directory);if(current.dev!==before.dev||current.ino!==before.ino)throw Error('status_directory_changed');
    fs.renameSync(temp,final);
  }finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temp);}catch(e){if(e.code!=='ENOENT')throw e;}}
}
export function pause(ms,signal) {
  if(signal?.aborted)return Promise.resolve();
  return new Promise(resolve=>{
    const done=()=>{clearTimeout(timer);signal?.removeEventListener('abort',done);resolve();};
    const timer=setTimeout(done,ms);signal?.addEventListener('abort',done,{once:true});
  });
}
export async function loop({read=readStatusFile,token=keychainToken,send=fetch,
  now=()=>new Date().toISOString(),clock=()=>performance.now(),wait=pause,
  publish=value=>writeStatus(installedDirectory(),value),signal}={}) {
  let credential,failures=0,lastCode,lastWrite=-Infinity;
  const cachedToken=()=>{if(credential===undefined)credential=token();return credential;};
  try {
    while(!signal?.aborted) {
      const started=clock();
      const result=await once({read,token:cachedToken,send,now,signal});
      if(signal?.aborted)break;
      // Keep diagnostic disk writes at <= one per 15 seconds when unchanged.
      // This does not slow HTTP uploads or change the source observation time.
      if(result.code!==lastCode||clock()-lastWrite>=15000){publish(result);lastCode=result.code;lastWrite=clock();}
      let interval;
      if(result.code==='uploaded'){failures=0;interval=1000;}
      else {
        failures=Math.min(failures+1,6);interval=Math.min(60000,1000*2**failures);
        if(result.code==='access_denied'||result.code==='keychain_unavailable'){
          credential=undefined;interval=60000;
        }
      }
      // Await completion before waiting/sending again: never overlapping POSTs
      // and no missed-deadline catch-up burst. Token stays only in this process.
      await wait(Math.max(0,interval-(clock()-started)),signal);
    }
  } finally {credential=undefined;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    if(!CONFIGURED||process.getuid()===0||process.geteuid()!==process.getuid()||process.argv.length!==2||
        fileURLToPath(import.meta.url)!==path.join(installedDirectory(),'uploader.mjs'))throw Error('fixed_ordinary_entry');
    const stop=new AbortController();
    for(const name of ['SIGTERM','SIGINT','SIGHUP'])process.once(name,()=>stop.abort());
    await loop({signal:stop.signal});
  }catch{process.exitCode=1;} // launchd stdio is /dev/null; never export exception context.
}
