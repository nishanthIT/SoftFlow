import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import {uploadFile,fingerprint} from '../src/lib/upload.ts';

test('fingerprint reads a file in bounded chunks without Web Crypto',async()=>{
  const data=Buffer.alloc(9*1024*1024,42);const file=new File([data],'test.exe');
  let largest=0;const original=file.slice.bind(file);
  file.slice=(start,end,type)=>{largest=Math.max(largest,(end||file.size)-(start||0));return original(start,end,type)};
  assert.equal(await fingerprint(file,new AbortController().signal,()=>{}),createHash('sha256').update(data).digest('hex'));
  assert.ok(largest<=8*1024*1024);
});

test('paused upload resumes committed offset with checksummed bytes and completes once',async()=>{
  const originalFetch=globalThis.fetch;const storage=new Map<string,string>();
  Object.defineProperty(globalThis,'localStorage',{configurable:true,value:{getItem:(key:string)=>storage.get(key)||null,setItem:(key:string,value:string)=>storage.set(key,value),removeItem:(key:string)=>storage.delete(key)}});
  let received=0,created=0,completed=0;const data=Buffer.from('a'.repeat(512));const file=new File([data],'same.exe');
  globalThis.fetch=(async(url:any,options:any={})=>{
    const path=String(url);const response=(value:unknown)=>new Response(JSON.stringify(value),{status:200});
    if(path==='/api/uploads'){created++;return response({id:'upload',size:512,received:0,state:'OPEN',chunk_bytes:256})}
    if(path==='/api/uploads/upload')return response({id:'upload',size:512,received,state:'OPEN',chunk_bytes:256});
    if(path.endsWith('/complete')){completed++;return response({analysis_id:'analysis',sha256:createHash('sha256').update(data).digest('hex')})}
    const offset=Number(path.split('/').at(-1));assert.equal(offset,received);
    const bytes=Buffer.from(options.body);assert.equal(options.headers['X-Chunk-SHA256'],createHash('sha256').update(bytes).digest('hex'));
    assert.deepEqual(bytes,data.subarray(offset,offset+bytes.length));received+=bytes.length;
    return response({id:'upload',size:512,received,state:'OPEN',chunk_bytes:256});
  }) as typeof fetch;
  try{
    const controller=new AbortController();
    await assert.rejects(uploadFile(file,false,controller.signal,p=>{if(p.phase==='uploading')controller.abort()},()=>{}),{name:'AbortError'});
    assert.equal(received,256);let resumed=false;
    const result=await uploadFile(file,false,new AbortController().signal,p=>{resumed ||= p.resumed},()=>{});
    assert.equal(result,'analysis');assert.equal(created,1);assert.equal(completed,1);assert.equal(received,512);assert.ok(resumed);assert.equal(storage.size,0);
  }finally{globalThis.fetch=originalFetch;delete (globalThis as any).localStorage}
});

test('product version changes never resume an upload declared for a different version',async()=>{
  const originalFetch=globalThis.fetch;const storage=new Map<string,string>();const identities:any[]=[];
  Object.defineProperty(globalThis,'localStorage',{configurable:true,value:{getItem:(key:string)=>storage.get(key)||null,setItem:(key:string,value:string)=>storage.set(key,value),removeItem:(key:string)=>storage.delete(key)}});
  const file=new File([Buffer.alloc(512)],'fixture.exe');let controller=new AbortController();
  globalThis.fetch=(async(url:any,options:any={})=>{
    assert.equal(url,'/api/uploads');const body=JSON.parse(options.body);identities.push(body.software_identity);
    controller.abort();return new Response(JSON.stringify({id:'upload'+identities.length,size:512,received:0,state:'OPEN',chunk_bytes:256}));
  }) as typeof fetch;
  try{
    for(const version of ['16.00','16.02']){
      controller=new AbortController();
      await assert.rejects(uploadFile(file,false,controller.signal,()=>{},()=>{},{name:'7-Zip',version}),{name:'AbortError'});
    }
    assert.deepEqual(identities,[{name:'7-Zip',version:'16.00'},{name:'7-Zip',version:'16.02'}]);
    assert.equal(storage.size,2);
  }finally{globalThis.fetch=originalFetch;delete (globalThis as any).localStorage}
});
