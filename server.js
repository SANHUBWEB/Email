// SANZONE Gmail backend: Google OAuth + Gmail API send. Refresh tokens are AES-256-GCM encrypted on disk.
const express=require('express'),{google}=require('googleapis'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const {GOOGLE_CLIENT_ID:CID,GOOGLE_CLIENT_SECRET:CS,BASE_URL,TOKEN_KEY}=process.env;
if(!CID||!CS||!BASE_URL||!TOKEN_KEY){console.error('Missing env vars. See README.');process.exit(1)}
const KEY=crypto.createHash('sha256').update(TOKEN_KEY).digest();
const FILE=process.env.DATA_FILE||path.join(__dirname,'data','store.json');fs.mkdirSync(path.dirname(FILE),{recursive:true});
let store={};try{store=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch{}
const save=()=>fs.writeFileSync(FILE,JSON.stringify(store),{mode:0o600});
const enc=t=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',KEY,iv),d=Buffer.concat([c.update(t,'utf8'),c.final()]);return [iv,c.getAuthTag(),d].map(b=>b.toString('base64')).join('.')};
const dec=s=>{const[iv,tag,d]=s.split('.').map(x=>Buffer.from(x,'base64')),c=crypto.createDecipheriv('aes-256-gcm',KEY,iv);c.setAuthTag(tag);return Buffer.concat([c.update(d),c.final()]).toString('utf8')};
const oauth=()=>new google.auth.OAuth2(CID,CS,BASE_URL+'/auth/callback');
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'30mb'}));
app.use((q,s,n)=>{s.set('X-Content-Type-Options','nosniff');const ck=Object.fromEntries((q.headers.cookie||'').split(/;\s*/).map(c=>c.split('=')));let sid=ck.sz_sid;
 if(!/^[a-f0-9]{48}$/.test(sid||'')){sid=crypto.randomBytes(24).toString('hex');s.append('Set-Cookie',`sz_sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000${BASE_URL.startsWith('https')?'; Secure':''}`)}
 q.sid=sid;store[sid]??={};n()});
const acc=q=>store[q.sid].accounts??={};
const guard=(q,s,n)=>q.get('x-requested-with')==='sanzone'?n():s.status(403).json({error:'Forbidden'});
const states=new Map();
app.get('/auth/google',(q,s)=>{const st=crypto.randomBytes(16).toString('hex');states.set(st,q.sid);setTimeout(()=>states.delete(st),6e5);
 s.redirect(oauth().generateAuthUrl({access_type:'offline',prompt:'consent',state:st,scope:['https://www.googleapis.com/auth/gmail.send','openid','email']}))});
app.get('/auth/callback',async(q,s)=>{try{const st=q.query.state;if(!st||states.get(st)!==q.sid)throw Error('bad state');states.delete(st);
 const o=oauth(),{tokens}=await o.getToken(q.query.code);o.setCredentials(tokens);
 const em=(await google.oauth2({version:'v2',auth:o}).userinfo.get()).data.email.toLowerCase(),a=acc(q),rt=tokens.refresh_token||(a[em]&&dec(a[em].rt));
 if(!rt)throw Error('no refresh token');a[em]={rt:enc(rt)};save();s.redirect('/?gmail=connected')}catch(e){console.error('oauth:',e.message);s.redirect('/?gmail=failed')}});
app.get('/api/accounts',guard,(q,s)=>s.json({accounts:Object.keys(acc(q))}));
app.delete('/api/accounts/:email',guard,async(q,s)=>{const a=acc(q),e=q.params.email.toLowerCase();if(a[e]){try{await oauth().revokeToken(dec(a[e].rt))}catch{}delete a[e];save()}s.json({ok:true})});
const MT={pdf:'application/pdf',jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',doc:'application/msword',docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document'};
const EM=/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/,cl=x=>String(x||'').replace(/[\r\n]+/g,' ').trim(),b64=t=>Buffer.from(t).toString('base64'),wrap=t=>t.replace(/.{1,76}/g,'$&\r\n');
const done=new Map();
app.post('/api/send',guard,async(q,s)=>{let dk;try{const{from,to,subject,body,attachments=[],key}=q.body||{},f=cl(from).toLowerCase(),a=acc(q);
 if(!a[f])return s.status(400).json({error:'Sender Gmail account is not connected'});
 const tos=cl(to).split(/\s*,\s*/);if(!tos.every(x=>EM.test(x)))return s.status(400).json({error:'Invalid recipient email'});
 if(!cl(subject)||!String(body||'').trim())return s.status(400).json({error:'Subject and body are required'});
 if(!key)return s.status(400).json({error:'Missing send key'});
 dk=q.sid+key;if(done.has(dk)){const d=done.get(dk);return d.pending?s.status(409).json({error:'This email is already being sent'}):s.json({...d,duplicate:true})}
 done.set(dk,{pending:true});setTimeout(()=>done.delete(dk),864e5);
 const bd='sz'+crypto.randomBytes(12).toString('hex');let tot=0;
 const m=[`From: ${f}`,`To: ${tos.join(', ')}`,`Subject: =?UTF-8?B?${b64(cl(subject))}?=`,'MIME-Version: 1.0',`Content-Type: multipart/mixed; boundary="${bd}"`,'',`--${bd}`,'Content-Type: text/plain; charset=UTF-8','Content-Transfer-Encoding: base64','',wrap(b64(String(body)))];
 for(const x of attachments){const ext=((cl(x.name).match(/\.(\w+)$/)||[])[1]||'').toLowerCase();if(!MT[ext]||typeof x.data!=='string')throw Error('File type not allowed: '+cl(x.name));tot+=x.data.length;if(tot>24e6)throw Error('Attachments too large (max about 15 MB)');
  const n=`=?UTF-8?B?${b64(cl(x.name))}?=`;m.push(`--${bd}`,`Content-Type: ${MT[ext]}; name="${n}"`,'Content-Transfer-Encoding: base64',`Content-Disposition: attachment; filename="${n}"`,'',wrap(x.data.replace(/[^A-Za-z0-9+\/=]/g,'')))}
 m.push(`--${bd}--`);
 const o=oauth();o.setCredentials({refresh_token:dec(a[f].rt)});
 const r=await google.gmail({version:'v1',auth:o}).users.messages.send({userId:'me',requestBody:{raw:Buffer.from(m.join('\r\n')).toString('base64url')}});
 const out={id:r.data.id,threadId:r.data.threadId,at:new Date().toISOString()};done.set(dk,out);s.json(out)}
 catch(e){if(dk)done.delete(dk);console.error('send:',e.message);s.status(500).json({error:/invalid_grant/.test(e.message)?'Gmail access expired. Disconnect and connect the account again.':e.message})}});
app.use(express.static(path.join(__dirname,'public')));
app.listen(process.env.PORT||3000,()=>console.log('SANZONE running at '+BASE_URL));
