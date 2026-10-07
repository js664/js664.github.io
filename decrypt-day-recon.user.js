// ==UserScript==
// @name         Decrypt.day Recon
// @namespace    https://decrypt.day/
// @version      1.1.0
// @description  Observer-only, redacting recorder for guided decrypt.day research.
// @match        https://decrypt.day/*
// @run-at       document-start
// @sandbox      raw
// @grant        none
// ==/UserScript==
(() => {
  'use strict';
  if (window.DECRYPT_DAY_RECON) {
    try { window.DECRYPT_DAY_RECON.start(); window.DECRYPT_DAY_RECON.showUi(); } catch {}
    return;
  }
  if (window.__ddReconInstalled) return;
  Object.defineProperty(window, '__ddReconInstalled', { value: true });
  const MAX = { timeline: 1800, net: 400, dom: 500, preview: 12000, body: 8000, mutationsPerBatch: 30 };
  const now = () => new Date().toISOString();
  const stack = () => { try { return String(new Error().stack || '').split('\n').slice(2, 9).join('\n'); } catch { return ''; } };
  const sensitiveKey = /(?:authorization|cookie|token|secret|csrf|session|signature|sig|key|api.?key|password|credential|clearance|nonce)/i;
  const redactString = (s) => String(s).replace(/\bBearer\s+[\w.~-]+/gi, 'Bearer <REDACTED_TOKEN>').replace(/\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}(?:\.[a-zA-Z0-9_-]*)?/g, '<REDACTED_JWT>').replace(/([?&](?:[^=&#]*(?:authorization|cookie|token|secret|csrf|session|signature|sig|api.?key|credential|clearance|nonce|password|policy)[^=&#]*)=)[^&#\s]*/gi, '$1<REDACTED>').replace(/(["']?(?:authorization|cookie|token|secret|csrf|session|signature|api.?key|credential|clearance|nonce|password)[\w-]*["']?\s*[:=]\s*["']?)([^"'&,\s}]+)/gi, '$1<REDACTED>');
  const safeUrl = (input) => { try { const u = new URL(String(input), location.href); for (const [k,v] of [...u.searchParams]) if (sensitiveKey.test(k)) u.searchParams.set(k, `<REDACTED:${v.length}>`); const out=redactString(u.href);return out.length>4096?out.slice(0,4096)+'…<TRUNCATED>':out; } catch { const out=redactString(input);return String(out).slice(0,4096); } };
  const safeObject = (value, depth=0) => { if(depth>8)return '<MAX_DEPTH>'; if(Array.isArray(value))return value.slice(0,100).map(v=>safeObject(v,depth+1)); if(value&&typeof value==='object'){const out={}; for(const [k,v] of Object.entries(value).slice(0,100))out[k]=sensitiveKey.test(k)?'<REDACTED>':safeObject(v,depth+1); return out;} return typeof value==='string'?redactString(value.slice(0,MAX.body)):value; };
  const safeFieldValue = (key,value) => { if(typeof value==='string'&&value.length>MAX.field&&!sensitiveKey.test(String(key))&&key!=='hasher')return redactString(value.slice(0,MAX.field))+'…<TRUNCATED>'; return safeValue(key,value); };
  const safeValue = (key, value) => {
    if (value == null) return value;
    if (typeof value === 'string') {
      if (key === 'body') { try { const parsed=JSON.parse(value); return {type:'json-text',length:value.length,value:safeObject(parsed)}; } catch {} }
      if (key === 'hasher') return { value: redactString(value.slice(0,512)) + (value.length>512?'…<TRUNCATED>':''), format: /^[\da-f]+$/i.test(value) ? 'hex-like' : 'text', length: value.length, empty: value.length === 0, hexadecimal: /^[\da-f]+$/i.test(value), truncated:value.length>512 };
      if (sensitiveKey.test(String(key))) return { redacted: true, length: String(value).length, type: 'string' };
      return redactString(value.slice(0, MAX.body)) + (value.length > MAX.body ? '…<TRUNCATED>' : '');
    }
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (value instanceof Blob) return { type: 'Blob', size: value.size, mimeType: value.type };
    if (value instanceof File) return { type: 'File', name: value.name, size: value.size, mimeType: value.type };
    try { return redactString(JSON.stringify(value).slice(0, MAX.body)); } catch { return { type: Object.prototype.toString.call(value) }; }
  };
  const blank = () => ({ schemaVersion:1, metadata:{ startedAt:now(), origin:location.origin }, environment:{ userAgent:navigator.userAgent, language:navigator.language, platform:navigator.platform }, pages:[], guidedSteps:[], timeline:[], network:{fetch:[],xhr:[],forms:[]}, formData:[], hasher:{observations:[]}, clicks:[], navigation:[], resources:[], scripts:[], dom:{snapshots:[],mutations:[]}, storage:{}, errors:[] });
  let data = blank(), active = true, panel;
  const push = (arr, item, limit=MAX.timeline) => { if (!active || !Array.isArray(arr)) return; try { arr.push(item); if (arr.length > limit) arr.splice(0, arr.length-limit); refreshCounters(); } catch {} };
  const log = (type, details={}) => push(data.timeline, {time:now(), type, url:safeUrl(location.href), ...details});
  const safeHeaders = (h) => { const out={}; try { new Headers(h || {}).forEach((v,k)=>out[k]=sensitiveKey.test(k)?'<REDACTED>':redactString(v)); } catch {} return out; };
  const bodyInfo = (body) => {
    if (body == null) return null;
    if (typeof body === 'string') return {type:'string', length:body.length, value:safeValue('body', body)};
    if (body instanceof URLSearchParams) { const fields={}; let n=0; for (const [k,v] of body) { if(n++>=MAX.formFields)break; fields[k]=safeFieldValue(k,v); } return {type:'URLSearchParams',fields,truncated:n>MAX.formFields}; }
    if (body instanceof FormData) { const fields=[]; let n=0; for (const [k,v] of body) { if(n++>=MAX.formFields)break; fields.push({name:k,value:safeFieldValue(k,v)}); } return {type:'FormData',fields,truncated:n>MAX.formFields}; }
    if (body instanceof Blob) return {type:'Blob',size:body.size,mimeType:body.type};
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return {type:'binary',size:body.byteLength};
    return {type:Object.prototype.toString.call(body)};
  };
  const preview = async (response) => {
    try {
      const ct=response.headers.get('content-type')||''; const len=Number(response.headers.get('content-length')||0);
      if (!/(json|text|xml|javascript|x-www-form-urlencoded)/i.test(ct) || (len && len>MAX.preview)) return null;
      const reader=response.clone().body?.getReader(); if(!reader) return null;
      let chunks=[], size=0;
      while(size<MAX.preview){ const {done,value}=await reader.read(); if(done) break; const take=value.subarray(0,MAX.preview-size); chunks.push(take); size+=take.length; if(take.length<value.length) break; }
      try { await reader.cancel(); } catch {}
      const bytes=new Uint8Array(size); let off=0; for(const c of chunks){bytes.set(c,off);off+=c.length;}
      return redactString(new TextDecoder().decode(bytes)).slice(0,MAX.preview)+(size>=MAX.preview?'…<TRUNCATED>':'');
    } catch { return null; }
  };
  // fetch: preserve receiver, arguments, return value, rejection, and response identity.
  try {
    const original=window.fetch;
    if(original) window.fetch=function(...args){
      if(!active)return original.apply(this,args);
      let rec=null;
      try { const started=now(), trace=stack(), req=args[0] instanceof Request?args[0]:null, url=safeUrl(req?.url||args[0]), method=String(args[1]?.method||req?.method||'GET').toUpperCase(); rec={startedAt:started,url,method,requestHeaders:safeHeaders(args[1]?.headers||req?.headers),body:bodyInfo(args[1]?.body),initiator:trace}; push(data.network.fetch,rec,MAX.net); log('fetch-request',{url,method,requestHeaders:rec.requestHeaders,body:rec.body}); } catch(e) { try{push(data.errors,{time:now(),kind:'fetch-recorder',message:redactString(e?.message||e)});}catch{} }
      let result; try { result=original.apply(this,args); } catch(e) { if(rec){rec.error=redactString(e?.message||e);rec.endedAt=now();} throw e; }
      if(!rec)return result;
      return result.then(async response=>{ try {rec.endedAt=now();rec.status=response.status;rec.responseUrl=safeUrl(response.url);rec.redirected=response.redirected;rec.responseType=response.type;rec.responseHeaders=safeHeaders(response.headers);rec.contentType=response.headers.get('content-type');rec.preview=await preview(response);log('fetch-response',{url:rec.url,status:rec.status,responseUrl:rec.responseUrl,redirected:rec.redirected});}catch(e){try{rec.recordingError=redactString(e?.message||e);}catch{}} return response;},err=>{try{rec.endedAt=now();rec.error=redactString(err?.message||err);}catch{} throw err;});
    };
  } catch(e){try{push(data.errors,{time:now(),kind:'instrumentation',message:String(e)});}catch{}}
  // XHR wrappers; methods are delegated unchanged.
  try {
    const X=window.XMLHttpRequest, op=X.prototype.open, sh=X.prototype.setRequestHeader, se=X.prototype.send;
    X.prototype.open=function(method,url,...rest){try{this.__ddr={startedAt:now(),method:String(method).toUpperCase(),url:safeUrl(url),requestHeaders:{},initiator:stack()};}catch{}return op.call(this,method,url,...rest);};
    X.prototype.setRequestHeader=function(k,v){try{if(this.__ddr)this.__ddr.requestHeaders[k]=sensitiveKey.test(k)?'<REDACTED>':redactString(v);}catch{}return sh.call(this,k,v);};
    X.prototype.send=function(body){const r=this.__ddr;try{if(r&&active){r.body=bodyInfo(body);push(data.network.xhr,r,MAX.net);log('xhr-request',{url:r.url,method:r.method,requestHeaders:r.requestHeaders,body:r.body});const done=()=>{if(r.endedAt)return;r.endedAt=now();try{r.status=this.status;r.responseUrl=safeUrl(this.responseURL);r.responseType=this.responseType;r.responseHeaders=safeHeaders(this.getAllResponseHeaders().split(/\r?\n/).filter(Boolean).map(x=>x.split(/:\s*(.*)/s).slice(0,2)));const ct=this.getResponseHeader('content-type');r.contentType=ct;log('xhr-response',{url:r.url,status:r.status,responseUrl:r.responseUrl});if(this.responseType===''||this.responseType==='text'){const t=this.responseText||'';r.preview=/json|text|xml/i.test(ct||'')?redactString(t.slice(0,MAX.preview)):null;}}catch{}};this.addEventListener('loadend',done,{once:true});this.addEventListener('error',()=>{try{r.error='network error';done();}catch{}},{once:true});}}catch{}return se.call(this,body);};
  } catch(e){try{push(data.errors,{time:now(),kind:'instrumentation',message:String(e)});}catch{}}
  // FormData observers: never rewrite values. If companion wraps this afterward, events reflect its visible input.
  for(const method of ['append','set']) try{const orig=FormData.prototype[method];FormData.prototype[method]=function(name,value,filename){try{const item={time:now(),method,name:String(name),value:safeValue(String(name),value),stack:stack(),pageUrl:safeUrl(location.href)};push(data.formData,item);log('formdata',{method,name:String(name),value:item.value});if(String(name)==='hasher')push(data.hasher.observations,{...item,format:item.value?.format,length:item.value?.length,empty:item.value?.empty,hexadecimal:item.value?.hexadecimal});}catch{}return orig.apply(this,arguments);};}catch(e){try{push(data.errors,{time:now(),kind:'instrumentation',message:String(e)});}catch{}}
  // Form submission observations.
  const formSnapshot=(form,submitter)=>{let fields=[];try{let n=0;for(const [k,v] of new FormData(form)){if(n++>=MAX.formFields)break;fields.push({name:k,value:safeFieldValue(k,v)});}}catch{}return {time:now(),action:safeUrl(form.action||location.href),method:(form.method||'get').toUpperCase(),enctype:form.enctype,fields,submitter:submitter?{tag:submitter.tagName,id:submitter.id||'',name:submitter.name||'',value:safeValue(submitter.name,submitter.value),text:(submitter.innerText||'').slice(0,120)}:null,stack:stack()};};
  try{document.addEventListener('submit',e=>{const r=formSnapshot(e.target,e.submitter);push(data.network.forms,r,MAX.net);log('form-submit',{action:r.action,method:r.method});},true);for(const m of ['submit','requestSubmit']){const orig=HTMLFormElement.prototype[m];HTMLFormElement.prototype[m]=function(submitter){const r=formSnapshot(this,m==='requestSubmit'?submitter:null);r.programmatic=m;push(data.network.forms,r,MAX.net);return orig.apply(this,arguments);};}}catch{}
  // Navigation observations.
  try{const wo=window.open;window.open=function(url,...args){push(data.navigation,{time:now(),kind:'window.open',url:safeUrl(url),stack:stack()});return wo.apply(this,[url,...args]);};for(const m of ['pushState','replaceState']){const orig=history[m];history[m]=function(state,title,url){push(data.navigation,{time:now(),kind:m,url:url==null?location.href:safeUrl(url),stack:stack()});return orig.apply(this,arguments);};}addEventListener('popstate',()=>push(data.navigation,{time:now(),kind:'popstate',url:safeUrl(location.href)}));addEventListener('hashchange',()=>push(data.navigation,{time:now(),kind:'hashchange',url:safeUrl(location.href)}));addEventListener('beforeunload',()=>push(data.navigation,{time:now(),kind:'beforeunload',url:safeUrl(location.href)}));addEventListener('pagehide',()=>push(data.navigation,{time:now(),kind:'pagehide',url:safeUrl(location.href)}));}catch{}
  // Errors
  addEventListener('error',e=>push(data.errors,{time:now(),kind:'error',message:redactString(e.message||''),source:safeUrl(e.filename||''),line:e.lineno,column:e.colno,stack:redactString(e.error?.stack||'')}));
  addEventListener('unhandledrejection',e=>push(data.errors,{time:now(),kind:'unhandledrejection',message:redactString(e.reason?.message||String(e.reason||'')),stack:redactString(e.reason?.stack||'')}));
  const relevant=(el)=>{try{return el?.matches?.('.download,.download-list,.dd-btn-disabled,ins.adsbygoogle,.note,[data-premier],[data-ad-status],[data-adsbygoogle-status],[data-load-state],[data-google-container-id]')||el?.closest?.('.download,.download-list,.dd-btn-disabled,ins.adsbygoogle,.note,[data-premier],[data-ad-status],[data-adsbygoogle-status],[data-load-state],[data-google-container-id]');}catch{return false;}};
  const nodeInfo=(el)=>{if(!(el instanceof Element))return null;return {tag:el.tagName,id:el.id||'',classes:String(el.className||'').slice(0,240),text:redactString((el.innerText||el.textContent||'').trim().slice(0,240)),attrs:[...el.attributes].filter(a=>/^(data-|disabled|href|name|type)/i.test(a.name)).slice(0,20).reduce((o,a)=>(o[a.name]=sensitiveKey.test(a.name)?'<REDACTED>':redactString(a.value).slice(0,512),o),{}),html:redactString((el.outerHTML||'').slice(0,1000))};};
  const snapshot=(label='manual')=>{const selectors='.download,.download-list,.dd-btn-disabled,ins.adsbygoogle,.note,[data-premier],[data-ad-status],[data-adsbygoogle-status],[data-load-state],[data-google-container-id]';let nodes=[];try{nodes=[...document.querySelectorAll(selectors)].slice(0,180).map(nodeInfo);}catch{};const s={time:now(),label,url:safeUrl(location.href),title:document.title,readyState:document.readyState,bodyText:redactString((document.body?.innerText||'').slice(0,3000)),nodes};push(data.dom.snapshots,s,160);data.pages.push({time:s.time,url:s.url,title:s.title,label});if(data.pages.length>100)data.pages.shift();log('snapshot',{label,nodeCount:nodes.length});return s;};
  // Bounded observer only records relevant added/changed nodes and observes no attributes.
  let mo;
  try {
    mo=new MutationObserver(ms=>{
      let recorded=0,seen=0;
      for(const m of ms){
        if(recorded>=MAX.mutationsPerBatch||seen++>=100)break;
        const added=m.addedNodes;
        for(let i=0;added&&i<added.length&&i<MAX.mutationsPerBatch&&recorded<MAX.mutationsPerBatch;i++){
          const el=added[i];if(!(el instanceof Element))continue;
          if(relevant(el)){push(data.dom.mutations,{time:now(),kind:'added',node:nodeInfo(el)},MAX.dom);recorded++;}
          let descendants;try{descendants=el.querySelectorAll?.('.download,.download-list,.dd-btn-disabled,ins.adsbygoogle,.note,[data-premier],[data-ad-status],[data-adsbygoogle-status],[data-load-state],[data-google-container-id]');}catch{}
          for(let j=0;descendants&&j<descendants.length&&j<MAX.mutationsPerBatch&&recorded<MAX.mutationsPerBatch;j++){
            push(data.dom.mutations,{time:now(),kind:'added-descendant',node:nodeInfo(descendants[j])},MAX.dom);recorded++;
          }
        }
        if(m.type==='childList'&&m.removedNodes.length&&relevant(m.target))push(data.dom.mutations,{time:now(),kind:'removed',target:nodeInfo(m.target),count:m.removedNodes.length},MAX.dom);
      }
    });
    const begin=()=>{if(document.documentElement)mo.observe(document.documentElement,{childList:true,subtree:true});};
    if(document.documentElement)begin();else addEventListener('DOMContentLoaded',begin,{once:true});
  } catch(e){push(data.errors,{time:now(),kind:'instrumentation',message:String(e)});}
  document.addEventListener('click',e=>{const el=e.target?.closest?.('a,button,[role="button"],input[type="submit"]');if(!el)return;const text=(el.innerText||el.value||'').trim().slice(0,200);const desc=[el.tagName,el.className,el.id,text,el.getAttribute('href'),...['data-premier','data-file-id','data-version-id'].map(k=>el.getAttribute(k)||'')].join(' ');if(!/download|file|version|ipa|premier/i.test(desc))return;push(data.clicks,{time:now(),tag:el.tagName,classes:String(el.className||''),id:el.id||'',href:safeUrl(el.href||el.getAttribute('href')||''),attributes:nodeInfo(el)?.attrs,text,nearby:el.parentElement?nodeInfo(el.parentElement):null,url:safeUrl(location.href),stack:stack()});log('click',{tag:el.tagName,text,href:safeUrl(el.href||el.getAttribute('href')||'')});},true);
  const inventory=()=>{try{data.scripts=[...document.scripts].slice(0,300).map(s=>({src:s.src?safeUrl(s.src):'',type:s.type||'',async:s.async,defer:s.defer,integrity:s.integrity||'',inlineLength:s.src?undefined:(s.textContent||'').length,inlineFingerprint:s.src?undefined:(()=>{let x=s.textContent||'';let h=2166136261;for(let i=0;i<x.length;i++)h=Math.imul(h^x.charCodeAt(i),16777619);return (h>>>0).toString(16);})()}));data.resources=performance.getEntriesByType('resource').slice(-500).map(r=>({name:safeUrl(r.name),initiatorType:r.initiatorType,duration:Math.round(r.duration),transferSize:r.transferSize,encodedBodySize:r.encodedBodySize})).filter(r=>/download|api|file|ipa|decrypt|version/i.test(r.name)||r.initiatorType==='fetch'||r.initiatorType==='xmlhttprequest');for(const k of ['localStorage','sessionStorage']){const out={};try{const s=window[k];for(let i=0;i<s.length&&i<100;i++){const key=s.key(i);const v=s.getItem(key)||'';out[key]=sensitiveKey.test(key)?{redacted:true,length:v.length}:{length:v.length,type:'string'};}}catch{}data.storage[k]=out;}}catch(e){push(data.errors,{time:now(),kind:'inventory',message:String(e)});}};
  const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  function refreshCounters(){if(!panel)return;const c={requests:data.network.fetch.length+data.network.xhr.length,hasher:data.hasher.observations.length,clicks:data.clicks.length,mutations:data.dom.mutations.length,errors:data.errors.length};for(const [k,v] of Object.entries(c)){const el=panel.querySelector(`[data-count="${k}"]`);if(el)el.textContent=v;}const s=panel.querySelector('#ddr-status');if(s)s.textContent=active?'ACTIVE · recording':'PAUSED';}
  function step(label,instruction){const item={time:now(),label,instruction,url:safeUrl(location.href)};push(data.guidedSteps,item,200);snapshot(label);const el=panel?.querySelector('#ddr-next');if(el)el.textContent=instruction;}
  function downloadJson(){inventory();data.metadata.endedAt=now();const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`decrypt-day-evidence-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),3000);}
  function summary(){inventory();return JSON.stringify({schemaVersion:1,metadata:data.metadata,pages:data.pages,guidedSteps:data.guidedSteps,counts:{fetch:data.network.fetch.length,xhr:data.network.xhr.length,forms:data.network.forms.length,formData:data.formData.length,hasher:data.hasher.observations.length,clicks:data.clicks.length,navigation:data.navigation.length,resources:data.resources.length,mutations:data.dom.mutations.length,errors:data.errors.length},hasher:data.hasher.observations,requests:[...data.network.fetch,...data.network.xhr].map(r=>({url:r.url||r.url,method:r.method,status:r.status,contentType:r.contentType,requestHeaders:r.requestHeaders,body:r.body,responseUrl:r.responseUrl,redirected:r.redirected})),scripts:data.scripts,storage:data.storage},null,2);}
  function mount(){
    if(panel||!document.documentElement)return;
    const el=(tag,parent,text='',id='')=>{const x=document.createElement(tag);if(text)x.textContent=text;if(id)x.id=id;if(parent)parent.appendChild(x);return x;};
    const button=(parent,id,text)=>{const x=el('button',parent,text,id);x.type='button';return x;};
    panel=el('section',null,'','dd-recon-panel');panel.tabIndex=-1;
    const header=el('header',panel);el('b',header,'Decrypt.day Recon');button(header,'ddr-collapse','−').title='Collapse';
    const body=el('div',panel);body.className='ddr-body';
    const status=el('div',body,'ACTIVE · recording','ddr-status');
    el('p',body,"Step 1: capture the baseline on the current page. Then use the site's search normally.",'ddr-next');
    const grid=el('div',body);grid.className='ddr-grid';
    const labels=['Baseline','App selected','Version/file selected','Before Download','Click Download','Download started/completed','Repeat example'];
    const buttonLabels=['Baseline Snapshot','After opening an app','After selecting a version/file','Before Download','Click Download marker','After download starts/completes','Repeat example'];
    for(let i=0;i<labels.length;i++){const b=button(grid,'',buttonLabels[i]);b.dataset.step=labels[i];}
    const counts=el('div',body);counts.className='ddr-counts';
    const counter=(name,label)=>{const span=el('span',counts,label+' ');const b=el('b',span,'0');b.setAttribute('data-count',name);el('span',counts,' · ');};
    counter('requests','Requests');counter('hasher','hasher');counter('clicks','clicks');counter('mutations','mutations');counter('errors','errors');
    const actions=el('div',body);actions.className='ddr-actions';
    button(actions,'ddr-export','Export JSON');button(actions,'ddr-copy','Copy Summary');button(actions,'ddr-snapshot','Snapshot Now');button(actions,'ddr-clear','Clear Recording');button(actions,'ddr-pause','Pause Recording');
    el('small',body,'Observer only. It does not click site controls, modify FormData, fetch extra endpoints, or download site files. Sensitive fields are redacted before recording.');
    const style=document.createElement('style');style.textContent=`#dd-recon-panel{position:fixed;z-index:2147483647;right:14px;bottom:14px;width:365px;max-height:82vh;overflow:auto;background:#10151f;color:#e9f0ff;border:1px solid #45536b;border-radius:14px;box-shadow:0 14px 48px #0009;font:13px/1.45 system-ui,sans-serif;padding:0}#dd-recon-panel *{box-sizing:border-box}#dd-recon-panel header{display:flex;justify-content:space-between;align-items:center;padding:11px 13px;background:#182233;position:sticky;top:0}#dd-recon-panel button{background:#263650;color:#f4f7ff;border:1px solid #465b7b;border-radius:7px;padding:7px 9px;cursor:pointer;font:inherit}#dd-recon-panel button:hover{background:#345078}#dd-recon-panel .ddr-body{padding:12px}#ddr-status{font-weight:700;color:#77e0ac}#ddr-next{background:#19273a;padding:9px;border-radius:8px;min-height:42px}.ddr-grid,.ddr-actions{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin:8px 0}.ddr-counts{padding:8px 0;color:#b8c6dd}#dd-recon-panel small{display:block;color:#aebbd0;margin-top:8px}#dd-recon-panel.ddr-mini{width:210px}#dd-recon-panel.ddr-mini .ddr-body{display:none}`;
    document.documentElement.appendChild(style);document.documentElement.appendChild(panel);
    panel.querySelectorAll('[data-step]').forEach(b=>b.addEventListener('click',()=>{const l=b.dataset.step;const instructions={'Baseline':'Baseline saved. Use the site search normally and open one app.','App selected':'App snapshot saved. Select a version or file using the site UI.','Version/file selected':'Selection snapshot saved. Stop before downloading, then press “Before Download.”','Before Download':'Pre-download snapshot saved. Now click the site’s real Download button once.','Click Download':'Marker saved. Click the site’s real Download control now, then wait for the normal flow.','Download started/completed':'Post-download snapshot saved. Repeat the same steps for two more examples.','Repeat example':'Example marker saved. Navigate to another app and repeat selection and download observations.'};step(l,instructions[l]||'Snapshot saved. Continue with the next normal site action.');}));
    panel.querySelector('#ddr-export').onclick=downloadJson;panel.querySelector('#ddr-copy').onclick=async()=>{try{await navigator.clipboard.writeText(summary());panel.querySelector('#ddr-next').textContent='Sanitized summary copied. Full evidence is available with Export JSON.';}catch(e){panel.querySelector('#ddr-next').textContent='Clipboard unavailable. Use Export JSON instead.';}};panel.querySelector('#ddr-snapshot').onclick=()=>snapshot('manual');panel.querySelector('#ddr-clear').onclick=()=>{data=blank();data.metadata.startedAt=now();panel.querySelector('#ddr-next').textContent='Recording cleared. Capture a new baseline.';refreshCounters();};panel.querySelector('#ddr-pause').onclick=e=>{active=!active;e.currentTarget.textContent=active?'Pause Recording':'Resume Recording';refreshCounters();};panel.querySelector('#ddr-collapse').onclick=()=>panel.classList.toggle('ddr-mini');refreshCounters();
  }
  const api = {
    version:'1.1.0',
    get active(){return active;},
    start(){active=true;if(document.documentElement)mount();refreshCounters();return api;},
    stop(){active=false;refreshCounters();return api;},
    snapshot(label='manual'){return snapshot(label);},
    export(){inventory();return JSON.stringify(data,null,2);},
    clear(){data=blank();refreshCounters();return data;},
    getData(){return data;},
    showUi(){if(document.documentElement)mount();if(panel){panel.hidden=false;panel.style.display='';panel.classList.remove('ddr-mini');panel.scrollIntoView?.({block:'nearest'});panel.focus?.();let toast=document.querySelector('#ddr-toast');if(!toast){toast=document.createElement('div');toast.id='ddr-toast';toast.textContent='Decrypt.day Recon active';toast.style.cssText='position:fixed;z-index:2147483647;right:18px;bottom:calc(82vh + 20px);background:#174d37;color:#fff;padding:10px 14px;border-radius:8px;font:600 14px system-ui';document.documentElement.appendChild(toast);setTimeout(()=>toast.remove(),2500);}}return Boolean(panel);}
  };
  window.DECRYPT_DAY_RECON=api;
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
  setTimeout(()=>{if(!api.showUi())document.addEventListener('DOMContentLoaded',()=>api.showUi(),{once:true});},0);
  addEventListener('load',()=>{inventory();snapshot('page-load');},{once:true});
})();
