/** Ordinary-user fixed installation. Does not provision or print a credential. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {CONFIGURED} from './uploader.mjs';
export const NODE=process.execPath;
export const LABEL='org.familyvpn.sites-monitor';
export const FILES=['uploader.mjs','model.mjs','daily_model_v2.mjs'];
const HERE=path.dirname(fileURLToPath(import.meta.url));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const xml=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
export function plist(directory){
  return Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${LABEL}</string>
<key>ProgramArguments</key><array><string>${xml(NODE)}</string><string>${xml(path.join(directory,'uploader.mjs'))}</string></array>
<key>KeepAlive</key><true/><key>RunAtLoad</key><true/>
<key>ProcessType</key><string>Background</string><key>ThrottleInterval</key><integer>15</integer>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string><key>LANG</key><string>C</string><key>LC_ALL</key><string>C</string></dict>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
<key>Umask</key><integer>63</integer></dict></plist>\n`);
}
function ownedDirectory(directory,mode){
  const s=fs.lstatSync(directory);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o022))throw Error('directory_unknown');
  if(mode!==undefined&&(s.mode&0o777)!==mode)throw Error('directory_mode');
}
function ensureDirectory(directory,mode){
  try{ownedDirectory(directory,mode);}catch(e){
    if(e.code!=='ENOENT')throw e;
    ownedDirectory(path.dirname(directory));fs.mkdirSync(directory,{mode});ownedDirectory(directory,mode);
  }
}
export function publishExact(filename,raw,mode){
  const parent=path.dirname(filename);ownedDirectory(parent);
  try{
    const s=fs.lstatSync(filename);
    if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o777)!==mode||s.size!==raw.length||!fs.readFileSync(filename).equals(raw))throw Error('existing_file_differs');
    return false;
  }catch(e){if(e.code!=='ENOENT')throw e;}
  const temp=path.join(parent,'.sites-'+crypto.randomUUID());let fd;
  try{
    fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,mode);
    fs.writeFileSync(fd,raw);fs.fchmodSync(fd,mode);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    fs.linkSync(temp,filename); // Atomic no-clobber publication; different existing files survive.
    fs.unlinkSync(temp);const dfd=fs.openSync(parent,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
    try{fs.fsyncSync(dfd);}finally{fs.closeSync(dfd);}
  }finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temp);}catch(e){if(e.code!=='ENOENT')throw e;}}
  return true;
}
function command(args){
  const p=spawnSync('/bin/launchctl',args,{stdio:['ignore','pipe','pipe'],encoding:'utf8',timeout:8000,maxBuffer:131072,
    env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin',LANG:'C',LC_ALL:'C'}});
  if(p.error)throw Error('launch_agent_unknown');return p;
}
function loaded(result,target,plistPath,entry){
  if(result.status!==0)throw Error('launch_agent_unverified');
  const lines=result.stdout.split('\n'), wanted={path:plistPath,type:'LaunchAgent',program:NODE,arguments:'{'};
  if(lines[0]!==target+' = {')throw Error('launch_agent_unknown');
  const actual={};let at=-1;
  for(let i=0;i<lines.length;i++){
    const match=/^\t([^\t=]+) = (.*)$/.exec(lines[i]);if(!match||!(match[1] in wanted))continue;
    if(match[1] in actual)throw Error('launch_agent_unknown');actual[match[1]]=match[2];if(match[1]==='arguments')at=i;
  }
  if(Object.keys(wanted).some(k=>wanted[k]!==actual[k])||
     lines.slice(at,at+4).join('\n')!==['\targuments = {','\t\t'+NODE,'\t\t'+entry,'\t}'].join('\n'))throw Error('launch_agent_unknown');
}
export function install({home=os.homedir(),run=command}={}){
  if(!CONFIGURED)throw Error('configure_private_site_before_install');
  if(process.getuid()===0||process.geteuid()!==process.getuid())throw Error('ordinary_user_only');
  const source=JSON.parse(fs.readFileSync(path.join(HERE,'source-pins.json'))),resources={};
  if(source.version!==1||JSON.stringify(Object.keys(source.files).sort())!==JSON.stringify(FILES.slice().sort()))throw Error('source_manifest');
  for(const name of FILES){const p=path.join(HERE,name),s=fs.lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>131072)throw Error('source_file');
    resources[name]=fs.readFileSync(p);if(sha(resources[name])!==source.files[name])throw Error('source_changed');}
  ownedDirectory(home);ownedDirectory(path.join(home,'Library'));ownedDirectory(path.join(home,'Library','Application Support'));
  const family=path.join(home,'Library','Application Support','Family VPN'),directory=path.join(family,'Sites');
  ensureDirectory(family,0o700);ensureDirectory(directory,0o700);
  const known=new Set([...FILES,'upload-status.json']);if(fs.readdirSync(directory).some(name=>!known.has(name)))throw Error('unknown_installed_file');
  for(const name of FILES)publishExact(path.join(directory,name),resources[name],0o600);
  const agents=path.join(home,'Library','LaunchAgents');try{ownedDirectory(agents);}catch(e){if(e.code!=='ENOENT')throw e;ensureDirectory(agents,0o755);}
  const plistPath=path.join(agents,LABEL+'.plist'),raw=plist(directory),target='gui/'+process.getuid()+'/'+LABEL;
  const old=run(['print',target]);
  if(old.status===0){
    publishExact(plistPath,raw,0o644);loaded(old,target,plistPath,path.join(directory,'uploader.mjs'));
    return {event:'sites_uploader_already_installed',uploads_verified:false};
  }
  const absent='Bad request.\nCould not find service "'+LABEL+'" in domain for user gui: '+process.getuid()+'\n';
  if(old.status!==113||old.stdout+old.stderr!==absent)throw Error('launch_agent_not_absent');
  publishExact(plistPath,raw,0o644);
  if(run(['bootstrap','gui/'+process.getuid(),plistPath]).status!==0)throw Error('launch_agent_load_unknown');
  loaded(run(['print',target]),target,plistPath,path.join(directory,'uploader.mjs'));
  return {event:'sites_uploader_installed',uploads_verified:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{if(process.argv.length!==2)throw Error('fixed_entry');console.log(JSON.stringify(install()));}
  catch{console.error(JSON.stringify({event:'sites_uploader_install_failed',existing_files_preserved:true}));process.exitCode=1;}
}
