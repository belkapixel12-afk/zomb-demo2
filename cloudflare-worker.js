var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// cloudflare-worker.js
var ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
var SESSION_DAYS = 30;
var MAX_AVATAR_CHARS = 14e4;
function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), { status, headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS,PATCH,DELETE",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Asset-Name",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  } });
}
__name(json, "json");
function err(message, status = 400) {
  return json({ error: message }, status);
}
__name(err, "err");
function newRoomCode() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => ALPHABET[b % ALPHABET.length]).join("");
}
__name(newRoomCode, "newRoomCode");
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(b64url, "b64url");
function randomToken(n = 32) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b64url(b);
}
__name(randomToken, "randomToken");
async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return b64url(new Uint8Array(b));
}
__name(sha256, "sha256");
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 1e5, hash: "SHA-256" }, key, 256);
  return b64url(new Uint8Array(bits));
}
__name(passwordHash, "passwordHash");
function safeName(v) {
  return String(v || "").replace(/[<>\u0000-\u001f]/g, "").trim().slice(0, 20);
}
__name(safeName, "safeName");
function isDeveloper(env, email) {
  const list = String(env.DEVELOPER_EMAILS || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  return list.includes(String(email || "").toLowerCase());
}
__name(isDeveloper, "isDeveloper");
function numericPublicId() {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  return String(1e7 + b[0] % 9e7);
}
__name(numericPublicId, "numericPublicId");
async function uniqueNumericPublicId(env) {
  for (let i = 0; i < 12; i++) {
    const id = numericPublicId();
    if (!await env.DB.prepare("SELECT 1 FROM users WHERE public_id=?").bind(id).first()) return id;
  }
  throw new Error("\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043F\u043E\u0434\u043E\u0431\u0440\u0430\u0442\u044C \u0441\u0432\u043E\u0431\u043E\u0434\u043D\u044B\u0439 ID");
}
__name(uniqueNumericPublicId, "uniqueNumericPublicId");
function validDeveloperId(v) {
  return /^[A-Za-z][A-Za-z0-9_-]{2,19}$/.test(String(v || ""));
}
__name(validDeveloperId, "validDeveloperId");
function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(v) && v.length <= 254;
}
__name(validEmail, "validEmail");
async function body(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}
__name(body, "body");
async function currentUser(request, env) {
  const raw = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!raw) return null;
  const hash = await sha256(raw);
  return await env.DB.prepare(`SELECT u.id,u.public_id,u.username,u.email,u.avatar,u.email_verified,u.created_at,a.account_kind,a.deadline,a.warning_shown,a.google_sub FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN auth_security a ON a.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash, Date.now()).first();
}
__name(currentUser, "currentUser");
function userView(u, env) {
  return clientUser(u,env);
}
__name(userView, "userView");
async function requireUser(request, env) {
  const user = await currentUser(request, env);
  return user;
}
__name(requireUser, "requireUser");
async function createSession(env, userId) {
  const token = randomToken(32), hash = await sha256(token), now = Date.now();
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)").bind(hash, userId, now, now + SESSION_DAYS * 864e5).run();
  return token;
}
__name(createSession, "createSession");
const WEEK_MS=7*86400000;
function blocked(u){return !!(u&&u.account_kind==='email'&&!u.email_verified&&u.deadline&&Date.now()>=u.deadline)}
function deviceEmail(u){return u.account_kind==='device'&&!u.google_sub}
function clientUser(u,env){return {id:u.id,publicId:u.public_id||null,role:isDeveloper(env,u.email)?"developer":"player",username:u.username,email:deviceEmail(u)?null:u.email,avatar:u.avatar||null,email_verified:!!u.email_verified,account_kind:u.account_kind||'email',deadline:u.deadline||null,warning_shown:!!u.warning_shown,google_linked:!!u.google_sub,locked:blocked(u)}}
async function userById(env,id){return env.DB.prepare('SELECT u.id,u.public_id,u.username,u.email,u.avatar,u.email_verified,u.created_at,s.account_kind,s.deadline,s.warning_shown,s.google_sub FROM users u LEFT JOIN auth_security s ON s.user_id=u.id WHERE u.id=?').bind(id).first()}
function validateNickname(name){return name.length>=3&&name.length<=20&&/^[\p{L}\p{N}_ .-]+$/u.test(name)}
function googleConfig(env,request){
 if(!env.GOOGLE_CLIENT_ID||!env.GOOGLE_CLIENT_SECRET||!env.GAME_URL)throw Error('Вход через Google не настроен: нужны GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET и GAME_URL в Worker.');
 let game;try{game=new URL(env.GAME_URL)}catch(_){throw Error('Некорректный GAME_URL')}
 if(game.protocol!=='https:'||game.hash||game.search)throw Error('GAME_URL должен быть HTTPS-адресом игры без параметров и фрагмента');
 const callback=new URL('/api/auth/google/callback',request.url).href;
 return {game:game.href,callback};
}
async function googleClaims(idToken,clientId,nonce){
 const parts=String(idToken||'').split('.');if(parts.length!==3)throw Error('Неверный токен Google');
 const dec=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s),c=>c.charCodeAt(0))))};
 const h=dec(parts[0]),c=dec(parts[1]);if(h.alg!=='RS256'||!h.kid)throw Error('Неверная подпись Google');
 const r=await fetch('https://www.googleapis.com/oauth2/v3/certs');if(!r.ok)throw Error('Не удалось проверить подпись Google');const jwks=await r.json(),jwk=(jwks.keys||[]).find(k=>k.kid===h.kid&&k.kty==='RSA');if(!jwk)throw Error('Ключ Google не найден');
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);const sig=Uint8Array.from(atob(parts[2].replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0));
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,new TextEncoder().encode(parts[0]+'.'+parts[1])))throw Error('Неверная подпись Google');
 const now=Math.floor(Date.now()/1000);if(!['accounts.google.com','https://accounts.google.com'].includes(c.iss)||c.aud!==clientId||!c.exp||c.exp<=now||c.iat>now+60||c.nonce!==nonce||!c.sub||c.email_verified!==true||!validEmail(String(c.email||'')))throw Error('Не удалось подтвердить аккаунт Google');
 return c;
}
async function authExtra(request,env,url){
 const p=url.pathname,method=request.method;
 if(p==='/api/auth/device/register'&&method==='POST'){
  const d=await body(request),username=safeName(d?.username);if(!validateNickname(username))return err('Ник: 3–20 символов, буквы, цифры, пробел, _ . -');
  if(await env.DB.prepare('SELECT id FROM users WHERE lower(username)=lower(?)').bind(username).first())return err('Этот ник уже занят',409);
  const id=randomToken(12),publicId=await uniqueNumericPublicId(env),deviceKey=randomToken(32),salt=randomToken(16),hash=await passwordHash(randomToken(32),salt),now=Date.now(),email='device-'+id.toLowerCase()+'@zomb.invalid';
  try{await env.DB.batch([env.DB.prepare('INSERT INTO users(id,public_id,username,email,password_salt,password_hash,avatar,created_at,last_seen,email_verified) VALUES(?,?,?,?,?,?,NULL,?,?,0)').bind(id,publicId,username,email,salt,hash,now,now),env.DB.prepare("INSERT INTO auth_security(user_id,account_kind,deadline,created_at) VALUES(?,'device',?,?)").bind(id,now+WEEK_MS,now),env.DB.prepare('INSERT INTO device_keys(token_hash,user_id,created_at) VALUES(?,?,?)').bind(await sha256(deviceKey),id,now)]);}catch(e){return err('Не удалось создать аккаунт. Возможно, ник занят.',409)}
  const token=await createSession(env,id);return json({token,deviceKey,user:clientUser(await userById(env,id),env)},201);
 }
 if(p==='/api/auth/device/restore'&&method==='POST'){
  const d=await body(request),k=String(d?.deviceKey||'');if(k.length!==43)return err('Ключ устройства недействителен',401);
  const row=await env.DB.prepare('SELECT user_id FROM device_keys WHERE token_hash=?').bind(await sha256(k)).first();if(!row)return err('Ключ устройства недействителен',401);
  const user=await userById(env,row.user_id);if(!user||blocked(user))return err('Подтверди почту через Google',403);
  return json({token:await createSession(env,user.id),user:clientUser(user,env)});
 }
 if(p==='/api/auth/google/start'&&method==='POST'){
  let cfg;try{cfg=googleConfig(env,request)}catch(e){return err(e.message,503)}
  const d=await body(request),action=d?.action==='link'?'link':'login',secretHash=String(d?.secretHash||'');if(!/^[A-Za-z0-9_-]{43}$/.test(secretHash))return err('Неверный запрос');
  let user=null;if(action==='link'){user=await currentUser(request,env);if(!user)return err('Войди в аккаунт, чтобы привязать почту',401)}
  const state=randomToken(32),verifier=randomToken(32),nonce=randomToken(32),nick=safeName(d?.username),now=Date.now();
  await env.DB.prepare('DELETE FROM google_flows WHERE expires_at<?').bind(now-86400000).run();
  await env.DB.prepare('INSERT INTO google_flows(state_hash,secret_hash,verifier,nonce,action,user_id,nickname,expires_at) VALUES(?,?,?,?,?,?,?,?)').bind(await sha256(state),secretHash,verifier,nonce,action,user?.id||null,nick,now+600000).run();
  const a=new URL('https://accounts.google.com/o/oauth2/v2/auth');for(const [k,v] of Object.entries({client_id:env.GOOGLE_CLIENT_ID,redirect_uri:cfg.callback,response_type:'code',scope:'openid email profile',state,nonce,code_challenge:await sha256(verifier),code_challenge_method:'S256',prompt:'select_account'}))a.searchParams.set(k,v);
  return json({url:a.href,state});
 }
 if(p==='/api/auth/google/callback'&&method==='GET'){
  let cfg;try{cfg=googleConfig(env,request)}catch(e){return new Response('Google OAuth не настроен',{status:503})}
  const state=String(url.searchParams.get('state')||'');if(!/^[A-Za-z0-9_-]{43}$/.test(state))return new Response('Неверный запрос',{status:400});
  const flow=await env.DB.prepare('SELECT * FROM google_flows WHERE state_hash=? AND status=\'pending\' AND consumed=0 AND expires_at>?').bind(await sha256(state),Date.now()).first();
  if(!flow)return new Response('Срок входа истёк; вернись в игру и попробуй снова.',{status:400});
  try{
   if(url.searchParams.get('error'))throw Error('Вход через Google отменён');const code=url.searchParams.get('code');if(!code)throw Error('Google не вернул код');
   const tr=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,redirect_uri:cfg.callback,grant_type:'authorization_code',code_verifier:flow.verifier})});if(!tr.ok)throw Error('Google отклонил вход');const tok=await tr.json(),g=await googleClaims(tok.id_token,env.GOOGLE_CLIENT_ID,flow.nonce),email=g.email.trim().toLowerCase();
   let owner=await env.DB.prepare('SELECT user_id FROM auth_security WHERE google_sub=?').bind(g.sub).first(),u=null;
   if(flow.action==='link'){
    u=await userById(env,flow.user_id);if(!u)throw Error('Аккаунт не найден');if(owner&&owner.user_id!==u.id)throw Error('Этот Google уже привязан к другому аккаунту');
    if(!deviceEmail(u)&&String(u.email).toLowerCase()!==email)throw Error('Почта Google должна совпадать с почтой аккаунта');
    const taken=await env.DB.prepare('SELECT id FROM users WHERE lower(email)=lower(?) AND id<>?').bind(email,u.id).first();if(taken)throw Error('Эта почта уже используется другим аккаунтом');
   } else if(owner)u=await userById(env,owner.user_id);
   else {
    const match=await env.DB.prepare('SELECT id FROM users WHERE lower(email)=lower(?)').bind(email).first();
    if(match){if(!(email.endsWith('@gmail.com')||g.hd))throw Error('Для этой почты сначала войди с паролем и привяжи Google в настройках');u=await userById(env,match.id)}
    else {const nickname=flow.nickname;if(!validateNickname(nickname))throw Error('Укажи свободный ник 3–20 символов перед входом через Google');if(await env.DB.prepare('SELECT id FROM users WHERE lower(username)=lower(?)').bind(nickname).first())throw Error('Этот ник уже занят');const now=Date.now(),id=randomToken(12),publicId=await uniqueNumericPublicId(env),salt=randomToken(16),ph=await passwordHash(randomToken(32),salt);await env.DB.batch([env.DB.prepare('INSERT INTO users(id,public_id,username,email,password_salt,password_hash,avatar,created_at,last_seen,email_verified) VALUES(?,?,?,?,?,?,NULL,?,?,1)').bind(id,publicId,nickname,email,salt,ph,now,now),env.DB.prepare("INSERT INTO auth_security(user_id,account_kind,google_sub,created_at) VALUES(?,'google',?,?)").bind(id,g.sub,now)]);u=await userById(env,id)}
   }
   await env.DB.batch([env.DB.prepare('UPDATE users SET email=?,email_verified=1 WHERE id=?').bind(email,u.id),env.DB.prepare('UPDATE auth_security SET google_sub=?,deadline=NULL WHERE user_id=?').bind(g.sub,u.id)]);
   await env.DB.prepare("UPDATE google_flows SET status='ready',result_user_id=?,verifier='' WHERE state_hash=? AND status='pending'").bind(u.id,await sha256(state)).run();
  }catch(e){console.error('Google flow error:',e.message);await env.DB.prepare("UPDATE google_flows SET status='error',result_error=?,verifier='' WHERE state_hash=? AND status='pending'").bind(String(e.message||'Ошибка входа').slice(0,250),await sha256(state)).run()}
  return Response.redirect(cfg.game+'#zgoogle='+encodeURIComponent(state),302);
 }
 if(p==='/api/auth/google/exchange'&&method==='POST'){
  const d=await body(request),state=String(d?.state||''),secret=String(d?.secret||'');if(state.length!==43||secret.length!==43)return err('Неверное завершение входа',400);
  const sh=await sha256(state),kh=await sha256(secret),row=await env.DB.prepare('SELECT * FROM google_flows WHERE state_hash=? AND secret_hash=? AND expires_at>? AND consumed=0').bind(sh,kh,Date.now()).first();if(!row)return err('Срок входа истёк. Попробуй снова.',400);if(row.status==='pending')return err('Вход ещё не завершён',409);
  const used=await env.DB.prepare('UPDATE google_flows SET consumed=1 WHERE state_hash=? AND consumed=0').bind(sh).run();if(!used.meta?.changes)return err('Вход уже использован',409);if(row.status==='error')return err(row.result_error||'Не удалось войти через Google',400);
  const u=await userById(env,row.result_user_id);if(!u)return err('Аккаунт не найден',404);return json({token:await createSession(env,u.id),user:clientUser(u,env)});
 }
 if(p==='/api/auth/warning/seen'&&method==='POST'){
  const u=await currentUser(request,env);if(!u)return err('Нужно войти',401);if(!u.deadline||Date.now()<u.deadline||u.email_verified)return err('Предупреждение пока не требуется');
  const r=await env.DB.prepare('UPDATE auth_security SET warning_shown=1 WHERE user_id=? AND warning_shown=0').bind(u.id).run();return json({show:!!r.meta?.changes});
 }
 return null;
}

async function api(request, env, url) {
  const p = url.pathname, method = request.method;
  if (p === "/api/health" && method === "GET") return json({ ok: true, service: "zomb" });
  const limits={'/api/auth/login':20,'/api/auth/register':10,'/api/auth/device/register':10,'/api/auth/device/restore':20,'/api/auth/google/start':20,'/api/auth/google/exchange':30,'/api/auth/email/send':8,'/api/auth/email/verify':20};
  const ip=request.headers.get('CF-Connecting-IP');
  if(method==='POST'&&ip&&limits[p]){const bucket=Math.floor(Date.now()/60000),id=await sha256(ip+':'+p+':'+bucket);
    await env.DB.prepare('INSERT INTO auth_limits(id,bucket,attempts) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET attempts=attempts+1').bind(id,bucket).run();
    const row=await env.DB.prepare('SELECT attempts FROM auth_limits WHERE id=?').bind(id).first();if(row.attempts>limits[p])return err('Слишком много попыток. Подожди минуту.',429);
    if(crypto.getRandomValues(new Uint16Array(1))[0]<64)await env.DB.prepare('DELETE FROM auth_limits WHERE bucket<?').bind(bucket-120).run();
  }
  const extra=await authExtra(request,env,url); if(extra) return extra;
  if (p === "/api/auth/register" && method === "POST") {
    const d = await body(request);
    if (!d) return err("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 JSON");
    const username = safeName(d.username), email = String(d.email || "").trim().toLowerCase(), password = String(d.password || "");
    if (username.length < 3 || username.length > 20 || !/^[\p{L}\p{N}_ .-]+$/u.test(username)) return err("\u041D\u0438\u043A: 3\u201320 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432, \u0431\u0443\u043A\u0432\u044B, \u0446\u0438\u0444\u0440\u044B, \u043F\u0440\u043E\u0431\u0435\u043B, _ . -");
    if (!validEmail(email)) return err("\u0423\u043A\u0430\u0436\u0438 \u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0443\u044E \u043F\u043E\u0447\u0442\u0443");
    if (password.length < 10 || password.length > 128) return err("\u041F\u0430\u0440\u043E\u043B\u044C \u0434\u043E\u043B\u0436\u0435\u043D \u0441\u043E\u0434\u0435\u0440\u0436\u0430\u0442\u044C \u043E\u0442 10 \u0434\u043E 128 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432");
    const exists = await env.DB.prepare("SELECT id FROM users WHERE lower(username)=lower(?) OR lower(email)=lower(?)").bind(username, email).first();
    if (exists) return err("\u042D\u0442\u043E\u0442 \u043D\u0438\u043A \u0438\u043B\u0438 \u043F\u043E\u0447\u0442\u0430 \u0443\u0436\u0435 \u0437\u0430\u043D\u044F\u0442\u044B", 409);
    const salt = randomToken(16), hash = await passwordHash(password, salt), now = Date.now(), id = randomToken(12), publicId = await uniqueNumericPublicId(env);
    try {
      await env.DB.prepare("INSERT INTO users (id,public_id,username,email,password_salt,password_hash,avatar,created_at,last_seen,email_verified) VALUES (?,?,?,?,?,?,NULL,?,?,0)").bind(id, publicId, username, email, salt, hash, now, now).run();
    } catch (e) {
      return err("\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0430\u043A\u043A\u0430\u0443\u043D\u0442: \u043D\u0438\u043A \u0438\u043B\u0438 \u043F\u043E\u0447\u0442\u0430 \u0443\u0436\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u044E\u0442\u0441\u044F", 409);
    }
    await env.DB.prepare("INSERT INTO auth_security(user_id,account_kind,deadline,created_at) VALUES(?,'email',?,?)").bind(id,now+WEEK_MS,now).run();
    const token = await createSession(env,id); return json({token,user:clientUser(await userById(env,id),env)},201);
  }
  if (p === "/api/auth/login" && method === "POST") {
    const d = await body(request);
    if (!d) return err("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 JSON");
    const email = String(d.email || "").trim().toLowerCase(), password = String(d.password || "");
    const u = await env.DB.prepare("SELECT u.id,u.public_id,u.username,u.email,u.password_salt,u.password_hash,u.avatar,u.email_verified,u.created_at,a.account_kind,a.deadline,a.warning_shown,a.google_sub FROM users u LEFT JOIN auth_security a ON a.user_id=u.id WHERE lower(u.email)=lower(?) AND COALESCE(a.account_kind,'email')<>'device'").bind(email).first();
    if (!u) return err("\u041D\u0435\u0432\u0435\u0440\u043D\u0430\u044F \u043F\u043E\u0447\u0442\u0430 \u0438\u043B\u0438 \u043F\u0430\u0440\u043E\u043B\u044C", 401);
    const h = await passwordHash(password, u.password_salt);
    if (h !== u.password_hash) return err("\u041D\u0435\u0432\u0435\u0440\u043D\u0430\u044F \u043F\u043E\u0447\u0442\u0430 \u0438\u043B\u0438 \u043F\u0430\u0440\u043E\u043B\u044C", 401);
    const token = await createSession(env, u.id);
    await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(), u.id).run();
    return json({ token, user: userView(u, env) });
  }
  if (p === "/api/auth/logout" && method === "POST") {
    const raw = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (raw) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(raw)).run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/auth/") || p === "/api/me" || p.startsWith("/api/profile") || p.startsWith("/api/friends") || p.startsWith("/api/users") || p.startsWith("/api/invites") || p === "/api/presence") {
    const user = await requireUser(request, env);
    if (!user) return err("Нужно войти в аккаунт",401);
    if(blocked(user)&&p!=="/api/me") return err("Аккаунт заблокирован до подтверждения почты через Google",403);
    if (p === "/api/me" && method === "GET") {
      await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(), user.id).run();
      return json({ user: userView(user, env) });
    }
    if (p === "/api/presence" && method === "POST") {
      await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(), user.id).run();
      return json({ ok: true });
    }
    if (p === "/api/profile" && method === "PATCH") {
      const d = await body(request);
      if (!d) return err("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 JSON");
      let username = user.username, avatar = user.avatar;
      if (d.username !== void 0) {
        username = safeName(d.username);
        if (username.length < 3 || username.length > 20 || !/^[\p{L}\p{N}_ .-]+$/u.test(username)) return err("\u041D\u0438\u043A: 3\u201320 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432, \u0431\u0443\u043A\u0432\u044B, \u0446\u0438\u0444\u0440\u044B, \u043F\u0440\u043E\u0431\u0435\u043B, _ . -");
        const taken = await env.DB.prepare("SELECT id FROM users WHERE lower(username)=lower(?) AND id<>?").bind(username, user.id).first();
        if (taken) return err("\u042D\u0442\u043E\u0442 \u043D\u0438\u043A \u0443\u0436\u0435 \u0437\u0430\u043D\u044F\u0442", 409);
      }
      let publicId = user.public_id;
      if (d.publicId !== void 0) {
        if (!isDeveloper(env, user.email)) return err("\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C\u0441\u043A\u0438\u0435 ID \u0441\u043E\u0441\u0442\u043E\u044F\u0442 \u0442\u043E\u043B\u044C\u043A\u043E \u0438\u0437 \u0446\u0438\u0444\u0440. \u0411\u0443\u043A\u0432\u0435\u043D\u043D\u044B\u0435 ID \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B \u0440\u0430\u0437\u0440\u0430\u0431\u043E\u0442\u0447\u0438\u043A\u0430\u043C.", 403);
        publicId = String(d.publicId || "").trim();
        if (!validDeveloperId(publicId)) return err("ID \u0440\u0430\u0437\u0440\u0430\u0431\u043E\u0442\u0447\u0438\u043A\u0430: 3\u201320 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432, \u043D\u0430\u0447\u0438\u043D\u0430\u0435\u0442\u0441\u044F \u0441 \u0431\u0443\u043A\u0432\u044B; \u0434\u0430\u043B\u0435\u0435 \u043B\u0430\u0442\u0438\u043D\u0441\u043A\u0438\u0435 \u0431\u0443\u043A\u0432\u044B, \u0446\u0438\u0444\u0440\u044B, _ \u0438\u043B\u0438 -");
        const takenId = await env.DB.prepare("SELECT id FROM users WHERE lower(public_id)=lower(?) AND id<>?").bind(publicId, user.id).first();
        if (takenId) return err("\u042D\u0442\u043E\u0442 ID \u0443\u0436\u0435 \u0437\u0430\u043D\u044F\u0442", 409);
      }
      if (d.avatar !== void 0) {
        avatar = d.avatar === null ? null : String(d.avatar);
        if (avatar && (!/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(avatar) || avatar.length > MAX_AVATAR_CHARS)) return err("\u0410\u0432\u0430\u0442\u0430\u0440 \u0434\u043E\u043B\u0436\u0435\u043D \u0431\u044B\u0442\u044C PNG/JPEG/WebP/GIF \u0438 \u043D\u0435 \u0431\u043E\u043B\u044C\u0448\u0435 \u043F\u0440\u0438\u043C\u0435\u0440\u043D\u043E 100 \u041A\u0411");
      }
      await env.DB.prepare("UPDATE users SET username=?,avatar=?,public_id=? WHERE id=?").bind(username, avatar, publicId, user.id).run();
      return json({user:clientUser({...user,username,avatar,public_id:publicId},env)});
    }
    if (p === "/api/users/search" && method === "GET") {
      const q = safeName(url.searchParams.get("q") || "");
      if (q.length < 2) return json({ users: [] });
      const result = await env.DB.prepare(`SELECT id,public_id,username,avatar,last_seen FROM users WHERE id<>? AND (lower(username) LIKE lower(?) ESCAPE '\\' OR lower(public_id)=lower(?)) ORDER BY username LIMIT 20`).bind(user.id, q.replace(/[\\%_]/g, "\\$&") + "%", q).all();
      return json({ users: (result.results || []).map((x) => ({ id: x.id, publicId: x.public_id, username: x.username, avatar: x.avatar, online: Date.now() - x.last_seen < 9e4 })) });
    }
    if (p === "/api/friends" && method === "GET") {
      const r = await env.DB.prepare(`SELECT f.id AS friendship_id,u.id,u.public_id,u.username,u.avatar,u.last_seen FROM friendships f JOIN users u ON u.id=CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END WHERE f.user_a=? OR f.user_b=? ORDER BY u.username`).bind(user.id, user.id, user.id).all();
      const req = await env.DB.prepare(`SELECT fr.id,fr.from_user,fr.to_user,fr.created_at,u.username,u.avatar FROM friend_requests fr JOIN users u ON u.id=fr.from_user WHERE fr.status='pending' AND fr.to_user=? ORDER BY fr.created_at DESC`).bind(user.id).all();
      const sent = await env.DB.prepare(`SELECT fr.id,fr.to_user,u.username,u.avatar,fr.created_at FROM friend_requests fr JOIN users u ON u.id=fr.to_user WHERE fr.status='pending' AND fr.from_user=? ORDER BY fr.created_at DESC`).bind(user.id).all();
      return json({ friends: (r.results || []).map((x) => ({ id: x.id, publicId: x.public_id, username: x.username, avatar: x.avatar, online: Date.now() - x.last_seen < 9e4, friendshipId: x.friendship_id })), requests: req.results || [], sent: sent.results || [] });
    }
    if (p === "/api/friends/request" && method === "POST") {
      const d = await body(request), target = String(d?.userId || "");
      if (!target || target === user.id) return err("\u041D\u0435\u043B\u044C\u0437\u044F \u0434\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u044D\u0442\u043E\u0442 \u0430\u043A\u043A\u0430\u0443\u043D\u0442");
      const other = await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(target).first();
      if (!other) return err("\u0418\u0433\u0440\u043E\u043A \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D", 404);
      const a = user.id < target ? user.id : target, b = user.id < target ? target : user.id;
      const fr = await env.DB.prepare("SELECT id FROM friendships WHERE user_a=? AND user_b=?").bind(a, b).first();
      if (fr) return err("\u0412\u044B \u0443\u0436\u0435 \u0434\u0440\u0443\u0437\u044C\u044F", 409);
      const reverse = await env.DB.prepare("SELECT id FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'").bind(target, user.id).first();
      if (reverse) {
        await env.DB.prepare("UPDATE friend_requests SET status='accepted',updated_at=? WHERE id=?").bind(Date.now(), reverse.id).run();
        await env.DB.prepare("INSERT OR IGNORE INTO friendships(id,user_a,user_b,created_at) VALUES (?,?,?,?)").bind(randomToken(12), a, b, Date.now()).run();
        return json({ ok: true, accepted: true });
      }
      const prior = await env.DB.prepare("SELECT id FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'").bind(user.id, target).first();
      if (prior) return err("\u0417\u0430\u044F\u0432\u043A\u0430 \u0443\u0436\u0435 \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u0430", 409);
      await env.DB.prepare("INSERT INTO friend_requests(id,from_user,to_user,status,created_at,updated_at) VALUES (?,?,?,'pending',?,?)").bind(randomToken(12), user.id, target, Date.now(), Date.now()).run();
      return json({ ok: true });
    }
    if (p === "/api/friends/respond" && method === "POST") {
      const d = await body(request), id = String(d?.requestId || ""), accept = !!d?.accept;
      const fr = await env.DB.prepare("SELECT id,from_user,to_user FROM friend_requests WHERE id=? AND to_user=? AND status='pending'").bind(id, user.id).first();
      if (!fr) return err("\u0417\u0430\u044F\u0432\u043A\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430", 404);
      await env.DB.prepare("UPDATE friend_requests SET status=?,updated_at=? WHERE id=?").bind(accept ? "accepted" : "rejected", Date.now(), id).run();
      if (accept) {
        const a = fr.from_user < fr.to_user ? fr.from_user : fr.to_user, b = fr.from_user < fr.to_user ? fr.to_user : fr.from_user;
        await env.DB.prepare("INSERT OR IGNORE INTO friendships(id,user_a,user_b,created_at) VALUES (?,?,?,?)").bind(randomToken(12), a, b, Date.now()).run();
      }
      return json({ ok: true });
    }
    if (p.startsWith("/api/friends/") && method === "DELETE") {
      const target = decodeURIComponent(p.slice("/api/friends/".length));
      if (!target) return err("\u041D\u0435 \u0443\u043A\u0430\u0437\u0430\u043D \u0434\u0440\u0443\u0433");
      const a = user.id < target ? user.id : target, b = user.id < target ? target : user.id;
      await env.DB.prepare("DELETE FROM friendships WHERE user_a=? AND user_b=?").bind(a, b).run();
      await env.DB.prepare("UPDATE friend_requests SET status='removed',updated_at=? WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)").bind(Date.now(), user.id, target, target, user.id).run();
      return json({ ok: true });
    }
    if (p === "/api/invites" && method === "GET") {
      const r = await env.DB.prepare(`SELECT i.id,i.room_code,i.created_at,i.expires_at,u.id AS from_id,u.username AS from_name,u.avatar AS from_avatar FROM game_invites i JOIN users u ON u.id=i.from_user WHERE i.to_user=? AND i.status='pending' AND i.expires_at>? ORDER BY i.created_at DESC LIMIT 30`).bind(user.id, Date.now()).all();
      return json({ invites: r.results || [] });
    }
    if (p === "/api/invites" && method === "POST") {
      const d = await body(request), friendId = String(d?.friendId || ""), room = String(d?.room || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
      if (!friendId || room.length < 6 || room.length > 12) return err("\u041D\u0443\u0436\u0435\u043D \u0434\u0440\u0443\u0433 \u0438 \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u044E\u0449\u0438\u0439 \u043A\u043E\u0434 \u043A\u043E\u043C\u043D\u0430\u0442\u044B");
      const a = user.id < friendId ? user.id : friendId, b = user.id < friendId ? friendId : user.id;
      const friendship = await env.DB.prepare("SELECT id FROM friendships WHERE user_a=? AND user_b=?").bind(a, b).first();
      if (!friendship) return err("\u041F\u0440\u0438\u0433\u043B\u0430\u0448\u0430\u0442\u044C \u043C\u043E\u0436\u043D\u043E \u0442\u043E\u043B\u044C\u043A\u043E \u0434\u0440\u0443\u0437\u0435\u0439", 403);
      const now = Date.now();
      await env.DB.prepare("INSERT INTO game_invites(id,from_user,to_user,room_code,status,created_at,expires_at) VALUES (?,?,?,?,'pending',?,?)").bind(randomToken(12), user.id, friendId, room, now, now + 15 * 60 * 1e3).run();
      return json({ ok: true });
    }
    if (p === "/api/invites/respond" && method === "POST") {
      const d = await body(request), id = String(d?.inviteId || ""), accept = !!d?.accept;
      const invite = await env.DB.prepare("SELECT id,room_code FROM game_invites WHERE id=? AND to_user=? AND status='pending' AND expires_at>?").bind(id, user.id, Date.now()).first();
      if (!invite) return err("\u041F\u0440\u0438\u0433\u043B\u0430\u0448\u0435\u043D\u0438\u0435 \u0438\u0441\u0442\u0435\u043A\u043B\u043E \u0438\u043B\u0438 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E", 404);
      await env.DB.prepare("UPDATE game_invites SET status=? WHERE id=?").bind(accept ? "accepted" : "rejected", id).run();
      return json({ ok: true, room: accept ? invite.room_code : null });
    }
    return err("\u041D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D API-\u043C\u0430\u0440\u0448\u0440\u0443\u0442", 404);
  }
  return null;
}
__name(api, "api");
// ZOMB stage33 API: account-bound cloud state, shareable configs and R2 assets.
function v2json(data,status=200){return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,PUT,OPTIONS,DELETE","Access-Control-Allow-Headers":"Content-Type,Authorization,X-Asset-Name","Cache-Control":"no-store","Vary":"Origin"}});}
function v2err(message,status=400){return v2json({error:message},status);}
function v2code(n=10){const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ";let s="";const b=new Uint8Array(n);crypto.getRandomValues(b);for(const x of b)s+=a[x%a.length];return s;}
async function v2api(request,env,url){
 const path=url.pathname,method=request.method;
 if(path==="/api/v2/capabilities"&&method==="GET")return v2json({version:33,inventory:true,configs:true,assets:!!env.ASSETS,emailVerification:true});
 if(!env.DB)return v2err("D1 binding DB не настроен",503);
 const assetMatch=path.match(/^\/api\/v2\/assets\/([A-Za-z0-9_-]+)$/);
 if(assetMatch&&method==="GET"){
   const row=await env.DB.prepare("SELECT object_key FROM cloud_assets WHERE id=?").bind(assetMatch[1]).first();
   if(!row||!env.ASSETS)return v2err("Файл не найден",404);
   const obj=await env.ASSETS.get(row.object_key);if(!obj)return v2err("Файл не найден",404);
   const h=new Headers();obj.writeHttpMetadata(h);h.set("Cache-Control","public, max-age=31536000, immutable");h.set("Access-Control-Allow-Origin","*");return new Response(obj.body,{headers:h});
 }
 const publicCfg=path.match(/^\/api\/v2\/configs\/([A-Z]{6,32})$/);
 if(publicCfg&&method==='GET'){
   const r=await env.DB.prepare('SELECT code,config_type,name,payload_json,created_at FROM shared_configs_all WHERE code=?').bind(publicCfg[1]).first();
   if(!r)return v2err('Конфигурация не найдена',404);
   await env.DB.prepare('UPDATE shared_configs_all SET downloads=downloads+1 WHERE code=?').bind(publicCfg[1]).run();
   return v2json({code:r.code,type:r.config_type,name:r.name,payload:JSON.parse(r.payload_json),createdAt:r.created_at});
 }
 const user=await currentUser(request,env);if(!user)return v2err("Нужно войти в аккаунт",401);if(blocked(user))return v2err("Аккаунт заблокирован до подтверждения почты через Google",403);
 if(path==="/api/v2/state"&&method==="GET"){
   const r=await env.DB.prepare("SELECT version,state_json,updated_at FROM player_states WHERE user_id=?").bind(user.id).first();
   return v2json({version:r?.version||0,state:r?JSON.parse(r.state_json):null,updatedAt:r?.updated_at||null});
 }
 if(path==="/api/v2/state"&&method==="PUT"){
   const d=await body(request);if(!d?.state||d.state.schema!==33)return v2err("Некорректное сохранение");
   const raw=JSON.stringify(d.state);if(raw.length>2_000_000)return v2err("Сохранение больше 2 МБ",413);
   const cur=await env.DB.prepare("SELECT version FROM player_states WHERE user_id=?").bind(user.id).first(),actual=cur?.version||0;
   if((Number(d.version)||0)!==actual)return v2json({error:"На другом устройстве уже есть более новая версия",version:actual},409);
   const next=actual+1,now=Date.now();
   await env.DB.prepare(`INSERT INTO player_states(user_id,version,state_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,state_json=excluded.state_json,updated_at=excluded.updated_at`).bind(user.id,next,raw,now).run();
   return v2json({ok:true,version:next,updatedAt:now});
 }
 if(path==="/api/v2/presence"&&method==="POST"){await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(),user.id).run();return v2json({ok:true});}
 if(path==="/api/v2/configs"&&method==="POST"){
   const d=await body(request);if(!d?.payload||!["controls","interface","themes","animations","sound","screen","language","lobby","music","profile"].includes(d.payload.type))return v2err("Неизвестный тип конфигурации");
   const name=String(d.name||"Моя конфигурация").trim().slice(0,80)||"Моя конфигурация",payload=JSON.stringify(d.payload);
   if(payload.length>1_000_000)return v2err("Конфигурация больше 1 МБ. Большие медиафайлы загружай отдельно.",413);
   let code=null;for(let i=0;i<8;i++){const candidate=v2code();if(!await env.DB.prepare("SELECT code FROM shared_configs_all WHERE code=?").bind(candidate).first()){code=candidate;break;}}
   if(!code)return v2err("Не удалось создать код",503);
   const now=Date.now();await env.DB.prepare("INSERT INTO shared_configs_all(code,owner_id,config_type,name,payload_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)").bind(code,user.id,d.payload.type,name,payload,now,now).run();
   return v2json({ok:true,code,name,createdAt:now},201);
 }
 const cfg=path.match(/^\/api\/v2\/configs\/([A-Z]{6,32})$/);
 if(cfg&&method==="GET"){
   const r=await env.DB.prepare("SELECT code,config_type,name,payload_json,created_at FROM shared_configs_all WHERE code=?").bind(cfg[1]).first();
   if(!r)return v2err("Конфигурация не найдена",404);
   await env.DB.prepare("UPDATE shared_configs_all SET downloads=downloads+1 WHERE code=?").bind(cfg[1]).run();
   return v2json({code:r.code,type:r.config_type,name:r.name,payload:JSON.parse(r.payload_json),createdAt:r.created_at});
 }
 if(cfg&&method==="DELETE"){
   const r=await env.DB.prepare("DELETE FROM shared_configs_all WHERE code=? AND owner_id=?").bind(cfg[1],user.id).run();
   if(!r.meta?.changes)return v2err("Конфигурация не найдена",404);return v2json({ok:true});
 }
 if(path==="/api/v2/assets"&&method==="POST"){
   if(!env.ASSETS)return v2err("R2 bucket не подключён (binding ASSETS)",503);
   const type=request.headers.get("Content-Type")||"application/octet-stream";
   if(!/^(image\/(png|jpeg|webp|gif)|audio\/[a-z0-9.+-]+|video\/[a-z0-9.+-]+|application\/octet-stream)$/i.test(type))return v2err("Тип файла запрещён",415);
   const bytes=await request.arrayBuffer();if(!bytes.byteLength||bytes.byteLength>75*1024*1024)return v2err("Файл пустой или больше 75 МБ",413);
   const id=randomToken(18),key=`users/${user.id}/${id}`,name=decodeURIComponent(request.headers.get("X-Asset-Name")||"media").slice(0,120);
   await env.ASSETS.put(key,bytes,{httpMetadata:{contentType:type}});
   await env.DB.prepare("INSERT INTO cloud_assets(id,owner_id,object_key,name,content_type,size_bytes,created_at) VALUES(?,?,?,?,?,?,?)").bind(id,user.id,key,name,type,bytes.byteLength,Date.now()).run();
   return v2json({ok:true,id,url:new URL(`/api/v2/assets/${id}`,url.origin).toString()},201);
 }
 return v2err("Неизвестный stage33 API-маршрут",404);
}

var cloudflare_worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS,PATCH,DELETE", "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Asset-Name", "Access-Control-Max-Age": "86400" } });
    if(url.pathname.startsWith("/api/v2/")){try{return await v2api(request,env,url)}catch(e){console.error("v2 API error",e);return v2err("Внутренняя ошибка облачного API",500)}}
    if (url.pathname.startsWith("/api/auth/") || url.pathname === "/api/me" || url.pathname.startsWith("/api/profile") || url.pathname.startsWith("/api/friends") || url.pathname.startsWith("/api/users") || url.pathname.startsWith("/api/invites") || url.pathname === "/api/presence" || url.pathname === "/api/health") {
      if (!env.DB) return err("D1 \u043D\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u0430. \u0412\u044B\u043F\u043E\u043B\u043D\u0438 \u043C\u0438\u0433\u0440\u0430\u0446\u0438\u044E \u0431\u0430\u0437\u044B \u0434\u0430\u043D\u043D\u044B\u0445.", 503);
      try {
        const response = await api(request, env, url);
        if (response) return response;
      } catch (e) {
        console.error("API error", e);
        return err("\u0412\u043D\u0443\u0442\u0440\u0435\u043D\u043D\u044F\u044F \u043E\u0448\u0438\u0431\u043A\u0430 API", 500);
      }
    }
    if (url.pathname === "/" && request.method === "GET") return new Response("zomb Worker is running (accounts + WebRTC signaling). Open the game HTML separately.", { headers: { "Content-Type": "text/plain; charset=utf-8" } });
    if (url.pathname === "/api/room" && request.method === "POST") {
      let code = newRoomCode();
      const id = env.ROOMS.idFromName(code);
      await env.ROOMS.get(id).fetch("https://room.internal/init", { method: "POST" });
      return json({ room: code });
    }
    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("Expected WebSocket", { status: 426 });
      const room = (url.searchParams.get("room") || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
      if (room.length < 6 || room.length > 12) return new Response("Invalid room code", { status: 400 });
      const id = env.ROOMS.idFromName(room);
      return env.ROOMS.get(id).fetch(request);
    }
    return err("Not found", 404);
  }
};
var Room = class {
  static {
    __name(this, "Room");
  }
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.host = null;
    this.guests = /* @__PURE__ */ new Map();
    this.clients = /* @__PURE__ */ new Map();
    this.nextPeer = 0;
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/init") return new Response("ok");
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    const role = url.searchParams.get("role"), name = safeName(url.searchParams.get("name") || (role === "host" ? "\u0425\u043E\u0441\u0442" : "\u0418\u0433\u0440\u043E\u043A"));
    if (role !== "host" && role !== "guest") return new Response("Invalid role", { status: 400 });
    if (role === "host" && this.host) return new Response("Room already has a host", { status: 409 });
    if (role === "guest" && !this.host) return new Response("Host is not connected yet", { status: 409 });
    if (role === "guest" && this.guests.size >= 15) return new Response("Room is full", { status: 409 });
    const pair = new WebSocketPair(), client = pair[0], server = pair[1];
    server.accept();
    const peerId = role === "guest" ? "P" + ++this.nextPeer : "host", meta = { role, name, peerId };
    this.clients.set(server, meta);
    if (role === "host") this.host = server;
    else this.guests.set(peerId, server);
    server.addEventListener("message", (ev) => this.onMessage(server, ev.data));
    server.addEventListener("close", () => this.onClose(server));
    server.addEventListener("error", () => this.onClose(server));
    send(server, { t: "sig:ready", role, peerId, room: url.searchParams.get("room") || "" });
    if (role === "guest") send(this.host, { t: "peer:join", peerId, name });
    return new Response(null, { status: 101, webSocket: client });
  }
  onMessage(ws, raw) {
    const meta = this.clients.get(ws);
    if (!meta) return;
    let m;
    try {
      m = JSON.parse(typeof raw === "string" ? raw : new TextDecoder().decode(raw));
    } catch {
      return;
    }
    if (m.t !== "signal" || !m.data || typeof m.data.type !== "string") return;
    if (meta.role === "host") {
      const guest = this.guests.get(String(m.to || ""));
      if (guest) send(guest, { t: "signal", from: "host", data: m.data });
    } else if (m.to === "host" && this.host) send(this.host, { t: "signal", from: meta.peerId, data: m.data });
  }
  onClose(ws) {
    const meta = this.clients.get(ws);
    if (!meta) return;
    this.clients.delete(ws);
    if (meta.role === "host") {
      this.host = null;
      for (const [, g] of this.guests) {
        send(g, { t: "err", msg: "\u0425\u043E\u0441\u0442 \u043E\u0442\u043A\u043B\u044E\u0447\u0438\u043B\u0441\u044F. \u041A\u043E\u043C\u043D\u0430\u0442\u0430 \u0437\u0430\u043A\u0440\u044B\u0442\u0430." });
        try {
          g.close(1001, "Host disconnected");
        } catch {
        }
      }
      this.guests.clear();
    } else {
      this.guests.delete(meta.peerId);
      if (this.host) send(this.host, { t: "peer:left", peerId: meta.peerId, name: meta.name });
    }
  }
};
function send(ws, obj) {
  try {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
  } catch {
  }
}
__name(send, "send");
export {
  Room,
  cloudflare_worker_default as default
};
//# sourceMappingURL=cloudflare-worker.js.map
