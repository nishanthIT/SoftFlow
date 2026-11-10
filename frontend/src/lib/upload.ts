import {sha256} from '@noble/hashes/sha2.js';
import {bytesToHex} from '@noble/hashes/utils.js';

export type UploadProgress={phase:'hashing'|'uploading'|'finalizing';bytes:number;total:number;bytesPerSecond:number;resumed:boolean};
export type SoftwareIdentity={name:string;version:string;vendor?:string};
type Upload={id:string;size:number;received:number;state:string;analysis_id?:string;chunk_bytes:number};
class UploadError extends Error {constructor(message:string,public status:number){super(message);}}
const CHUNK=8*1024*1024;
const wait=(ms:number,signal:AbortSignal)=>new Promise<void>((resolve,reject)=>{
  const abort=()=>{clearTimeout(timer);reject(new DOMException('Upload paused','AbortError'))};
  const timer=setTimeout(()=>{signal.removeEventListener('abort',abort);resolve()},ms);
  if(signal.aborted)abort();else signal.addEventListener('abort',abort,{once:true});
});
function saved(key:string,value?:string|null){try{if(value===undefined)return localStorage.getItem(key);if(value===null)localStorage.removeItem(key);else localStorage.setItem(key,value)}catch{/* Upload still works when browser storage is disabled. */}return null;}

async function request<T>(url:string,init:RequestInit,signal:AbortSignal):Promise<T>{
  for(let attempt=0;;attempt++){
    signal.throwIfAborted();
    try{
      const response=await fetch(url,{...init,signal:AbortSignal.any([signal,AbortSignal.timeout(180000)])});
      const data=await response.json().catch(()=>({}));
      if(!response.ok)throw new UploadError(typeof data.detail==='string'?data.detail:`Upload request failed (${response.status})`,response.status);
      return data as T;
    }catch(error){
      signal.throwIfAborted();
      const retryable=!(error instanceof UploadError)||[408,429,502,503,504].includes(error.status);
      if(!retryable||attempt>=3)throw error;
      await wait(1000*2**attempt,signal);
    }
  }
}

// Read at most one chunk at a time, including fingerprinting. Full-file identity
// prevents resuming old chunks into a different file with the same name/size.
export async function fingerprint(file:File,signal:AbortSignal,progress:(p:UploadProgress)=>void){
  const hash=sha256.create();const started=performance.now();
  for(let offset=0;offset<file.size;offset+=CHUNK){
    signal.throwIfAborted();
    hash.update(new Uint8Array(await file.slice(offset,offset+CHUNK).arrayBuffer()));
    const bytes=Math.min(offset+CHUNK,file.size);
    progress({phase:'hashing',bytes,total:file.size,bytesPerSecond:bytes/Math.max((performance.now()-started)/1000,.01),resumed:false});
  }
  return bytesToHex(hash.digest());
}

export async function uploadFile(file:File,consent:boolean,signal:AbortSignal,progress:(p:UploadProgress)=>void,onSession:(id:string)=>void,softwareIdentity?:SoftwareIdentity){
  const digest=await fingerprint(file,signal,progress);
  const key=`sentinel-upload-v1:${digest}:${consent}:${JSON.stringify(softwareIdentity||{})}`;
  let upload:Upload|undefined;
  const previous=saved(key);
  if(previous){
    try{upload=await request<Upload>(`/api/uploads/${previous}`,{},signal)}catch(error){if(!(error instanceof UploadError)||error.status!==404)throw error;saved(key,null)}
  }
  if(!upload){
    upload=await request<Upload>('/api/uploads',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:file.name,size:file.size,external_consent:consent,software_identity:softwareIdentity})},signal);
    saved(key,upload.id);
  }
  onSession(upload.id);
  if(upload.size!==file.size||!Number.isSafeInteger(upload.received)||upload.received<0||upload.received>file.size)throw new Error('Stored upload does not match this file. Discard it and retry.');
  if(upload.state==='COMPLETED'&&upload.analysis_id){saved(key,null);return upload.analysis_id}
  const resumed=upload.received>0;const initial=upload.received;const started=performance.now();
  if(!Number.isSafeInteger(upload.chunk_bytes)||upload.chunk_bytes<=0||upload.chunk_bytes>16*1024*1024)throw new Error('Server returned an invalid upload chunk size');
  while(upload.received<file.size){
    signal.throwIfAborted();
    const offset:number=upload.received;
    const buffer=await file.slice(offset,offset+upload.chunk_bytes).arrayBuffer();
    const expected=Math.min(offset+buffer.byteLength,file.size);
    upload=await request<Upload>(`/api/uploads/${upload.id}/chunks/${offset}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream','X-Chunk-SHA256':bytesToHex(sha256(new Uint8Array(buffer)))},body:buffer},signal);
    if(upload.received!==expected)throw new Error('Server returned an unexpected upload offset');
    progress({phase:'uploading',bytes:upload.received,total:file.size,bytesPerSecond:(upload.received-initial)/Math.max((performance.now()-started)/1000,.01),resumed});
  }
  progress({phase:'finalizing',bytes:file.size,total:file.size,bytesPerSecond:0,resumed});
  const result=await request<{analysis_id:string;sha256?:string}>(`/api/uploads/${upload.id}/complete`,{method:'POST'},signal);
  if(result.sha256&&result.sha256!==digest)throw new Error('Final file checksum differs from the selected file. Do not use this analysis.');
  saved(key,null);
  return result.analysis_id;
}

export async function discardUpload(identifier:string){
  const response=await fetch(`/api/uploads/${identifier}`,{method:'DELETE'});
  if(!response.ok&&response.status!==404)throw new Error('Unable to discard upload. Retry when the service is available.');
  try{for(const key of Object.keys(localStorage))if(key.startsWith('sentinel-upload-v1:')&&localStorage.getItem(key)===identifier)localStorage.removeItem(key)}catch{/* Optional resume storage. */}
}
