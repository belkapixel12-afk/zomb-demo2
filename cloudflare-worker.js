// zomb: accounts/social API + WebRTC signaling. Game traffic remains peer-to-peer.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const SESSION_DAYS = 30;
const MAX_AVATAR_CHARS = 140000;

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), { status, headers: {
    "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS,PATCH,DELETE", "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Asset-Name",
    "Cache-Control": "no-store", "Vary": "Origin"
  }});
}
function err(message, status=400){ return json({error:message},status); }
function newRoomCode() { const bytes = new Uint8Array(8); crypto.getRandomValues(bytes); return [...bytes].map(b => ALPHABET[b % ALPHABET.length]).join(""); }
function b64url(bytes){ let s=""; for(const b of bytes)s+=String.fromCharCode(b); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
function randomToken(n=32){const b=new Uint8Array(n);crypto.getRandomValues(b);return b64url(b);}
async function sha256(s){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return b64url(new Uint8Array(b));}
async function passwordHash(password, salt){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:210000,hash:"SHA-256"},key,256);return b64url(new Uint8Array(bits));}
function safeName(v){return String(v||"").replace(/[<>\u0000-\u001f]/g,"").trim().slice(0,20);}
function validEmail(v){return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(v) && v.length<=254;}
async function body(request){try{return await request.json();}catch{return null;}}
async function currentUser(request,env){const raw=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"").trim();if(!raw)return null;const hash=await sha256(raw);return await env.DB.prepare(`SELECT u.id,u.username,u.email,u.avatar,u.email_verified FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash,Date.now()).first();}
function userView(u){return {id:u.id,username:u.username,email:u.email,avatar:u.avatar||null,email_verified:!!u.email_verified};}
async function requireUser(request,env){const user=await currentUser(request,env);return user;}
async function createSession(env,userId){const token=randomToken(32),hash=await sha256(token),now=Date.now();await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)").bind(hash,userId,now,now+SESSION_DAYS*86400000).run();return token;}

async function sendResendEmail(env,to,subject,html){
  if(!env.RESEND_API_KEY||!env.EMAIL_FROM)throw new Error("Почтовая отправка не настроена: добавь RESEND_API_KEY и EMAIL_FROM в Worker Secrets/Variables");
  const res=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"Authorization":"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.EMAIL_FROM,to:[to],subject,html})});
  if(!res.ok){const t=await res.text();console.error("Resend error",res.status,t.slice(0,500));throw new Error("Почтовый сервис не принял письмо. Проверь домен отправителя и настройки Resend.");}
}
async function issueEmailCode(env,user,purpose){
  const now=Date.now();
  const recent=await env.DB.prepare("SELECT created_at FROM email_codes WHERE user_id=? AND purpose=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1").bind(user.id,purpose).first();
  if(recent&&now-recent.created_at<60000)throw new Error("Подожди минуту перед повторной отправкой кода");
  const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0");
  const hash=await sha256(user.id+":"+purpose+":"+code);
  await env.DB.prepare("UPDATE email_codes SET used_at=? WHERE user_id=? AND purpose=? AND used_at IS NULL").bind(now,user.id,purpose).run();
  await env.DB.prepare("INSERT INTO email_codes(id,user_id,email,purpose,code_hash,expires_at,attempts,created_at) VALUES(?,?,?,?,?,?,0,?)")
    .bind(randomToken(12),user.id,user.email,purpose,hash,now+15*60*1000,now).run();
  const title="Код подтверждения ZOMB";
  const bodyHtml=`<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;color:#222"><h2>ZOMB</h2><p>Твой код подтверждения:</p><div style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:16px;background:#f1f3f5;border-radius:10px;text-align:center">${code}</div><p>Код действует 15 минут. Никому его не сообщай.</p><p>Если ты не запрашивал письмо, просто проигнорируй его.</p></div>`;
  await sendResendEmail(env,user.email,title,bodyHtml);
}

async function api(request,env,url){
  const p=url.pathname,method=request.method;
  if(p==="/api/health"&&method==="GET")return json({ok:true,service:"zomb"});
  if(p==="/api/auth/register"&&method==="POST"){
    const d=await body(request);if(!d)return err("Некорректный JSON");const username=safeName(d.username),email=String(d.email||"").trim().toLowerCase(),password=String(d.password||"");
    if(username.length<3||username.length>20||!/^[\p{L}\p{N}_ .-]+$/u.test(username))return err("Ник: 3–20 символов, буквы, цифры, пробел, _ . -");
    if(!validEmail(email))return err("Укажи корректную почту");if(password.length<10||password.length>128)return err("Пароль должен содержать от 10 до 128 символов");
    const exists=await env.DB.prepare("SELECT id FROM users WHERE lower(username)=lower(?) OR lower(email)=lower(?)").bind(username,email).first();if(exists)return err("Этот ник или почта уже заняты",409);
    const salt=randomToken(16),hash=await passwordHash(password,salt),now=Date.now(),id=randomToken(12);
    try{await env.DB.prepare("INSERT INTO users (id,username,email,password_salt,password_hash,avatar,created_at,last_seen,email_verified) VALUES (?,?,?,?,?,NULL,?,?,0)").bind(id,username,email,salt,hash,now,now).run();}
    catch(e){return err("Не удалось создать аккаунт: ник или почта уже используются",409)}
    const token=await createSession(env,id);return json({token,user:{id,username,email,avatar:null}} ,201);
  }
  if(p==="/api/auth/login"&&method==="POST"){
    const d=await body(request);if(!d)return err("Некорректный JSON");const email=String(d.email||"").trim().toLowerCase(),password=String(d.password||"");const u=await env.DB.prepare("SELECT id,username,email,password_salt,password_hash,avatar,email_verified FROM users WHERE lower(email)=lower(?)").bind(email).first();
    if(!u)return err("Неверная почта или пароль",401);const h=await passwordHash(password,u.password_salt);if(h!==u.password_hash)return err("Неверная почта или пароль",401);
    if(!u.email_verified)return err("Почта не подтверждена. Открой игру на устройстве, где регистрировался, и запроси код подтверждения.",403);
    const token=await createSession(env,u.id);await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(),u.id).run();return json({token,user:userView(u)});
  }
  if(p==="/api/auth/logout"&&method==="POST"){
    const raw=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"").trim();if(raw)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(raw)).run();return json({ok:true});
  }
  if(p.startsWith("/api/auth/")||p==="/api/me"||p.startsWith("/api/profile")||p.startsWith("/api/friends")||p.startsWith("/api/users")||p.startsWith("/api/invites")||p==="/api/presence"){
    const user=await requireUser(request,env);if(!user)return err("Нужно войти в аккаунт",401);
    if(p==="/api/auth/email/send"&&method==="POST"){
      if(user.email_verified)return json({ok:true,verified:true});
      try{await issueEmailCode(env,user,"verify");return json({ok:true,message:"Код отправлен на почту"});}
      catch(e){return err(e.message||"Не удалось отправить письмо",503);}
    }
    if(p==="/api/auth/email/verify"&&method==="POST"){
      const d=await body(request),code=String(d?.code||"").trim();
      if(!/^\\d{6}$/.test(code))return err("Введи шестизначный код");
      const row=await env.DB.prepare("SELECT id,code_hash,expires_at,attempts FROM email_codes WHERE user_id=? AND purpose='verify' AND used_at IS NULL ORDER BY created_at DESC LIMIT 1").bind(user.id).first();
      if(!row||row.expires_at<Date.now())return err("Код истёк. Запроси новый.",400);
      if(row.attempts>=5)return err("Слишком много попыток. Запроси новый код.",429);
      const hash=await sha256(user.id+":verify:"+code);
      if(hash!==row.code_hash){await env.DB.prepare("UPDATE email_codes SET attempts=attempts+1 WHERE id=?").bind(row.id).run();return err("Неверный код",400);}
      await env.DB.batch([
        env.DB.prepare("UPDATE email_codes SET used_at=? WHERE id=?").bind(Date.now(),row.id),
        env.DB.prepare("UPDATE users SET email_verified=1 WHERE id=?").bind(user.id)
      ]);
      return json({ok:true,verified:true});
    }
    if(p==="/api/me"&&method==="GET"){await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(),user.id).run();return json({user:userView(user)});}
    if(p==="/api/presence"&&method==="POST"){await env.DB.prepare("UPDATE users SET last_seen=? WHERE id=?").bind(Date.now(),user.id).run();return json({ok:true});}
    if(p==="/api/profile"&&method==="PATCH"){
      const d=await body(request);if(!d)return err("Некорректный JSON");let username=user.username,avatar=user.avatar;
      if(d.username!==undefined){username=safeName(d.username);if(username.length<3||username.length>20||!/^[\p{L}\p{N}_ .-]+$/u.test(username))return err("Ник: 3–20 символов, буквы, цифры, пробел, _ . -");const taken=await env.DB.prepare("SELECT id FROM users WHERE lower(username)=lower(?) AND id<>?").bind(username,user.id).first();if(taken)return err("Этот ник уже занят",409);}
      if(d.avatar!==undefined){avatar=d.avatar===null?null:String(d.avatar);if(avatar&&(!/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(avatar)||avatar.length>MAX_AVATAR_CHARS))return err("Аватар должен быть PNG/JPEG/WebP/GIF и не больше примерно 100 КБ");}
      await env.DB.prepare("UPDATE users SET username=?,avatar=? WHERE id=?").bind(username,avatar,user.id).run();return json({user:{...user,username,avatar}});
    }
    if(p==="/api/users/search"&&method==="GET"){
      const q=safeName(url.searchParams.get("q")||"");if(q.length<2)return json({users:[]});const result=await env.DB.prepare(`SELECT id,username,avatar,last_seen FROM users WHERE id<>? AND lower(username) LIKE lower(?) ESCAPE '\\' ORDER BY username LIMIT 20`).bind(user.id,q.replace(/[\\%_]/g,"\\$&")+"%").all();return json({users:(result.results||[]).map(x=>({id:x.id,username:x.username,avatar:x.avatar,online:Date.now()-x.last_seen<90000}))});
    }
    if(p==="/api/friends"&&method==="GET"){
      const r=await env.DB.prepare(`SELECT f.id AS friendship_id,u.id,u.username,u.avatar,u.last_seen FROM friendships f JOIN users u ON u.id=CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END WHERE f.user_a=? OR f.user_b=? ORDER BY u.username`).bind(user.id,user.id,user.id).all();
      const req=await env.DB.prepare(`SELECT fr.id,fr.from_user,fr.to_user,fr.created_at,u.username,u.avatar FROM friend_requests fr JOIN users u ON u.id=fr.from_user WHERE fr.status='pending' AND fr.to_user=? ORDER BY fr.created_at DESC`).bind(user.id).all();
      const sent=await env.DB.prepare(`SELECT fr.id,fr.to_user,u.username,u.avatar,fr.created_at FROM friend_requests fr JOIN users u ON u.id=fr.to_user WHERE fr.status='pending' AND fr.from_user=? ORDER BY fr.created_at DESC`).bind(user.id).all();
      return json({friends:(r.results||[]).map(x=>({id:x.id,username:x.username,avatar:x.avatar,online:Date.now()-x.last_seen<90000,friendshipId:x.friendship_id})),requests:req.results||[],sent:sent.results||[]});
    }
    if(p==="/api/friends/request"&&method==="POST"){
      const d=await body(request),target=String(d?.userId||"");if(!target||target===user.id)return err("Нельзя добавить этот аккаунт");const other=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(target).first();if(!other)return err("Игрок не найден",404);
      const a=user.id<target?user.id:target,b=user.id<target?target:user.id;const fr=await env.DB.prepare("SELECT id FROM friendships WHERE user_a=? AND user_b=?").bind(a,b).first();if(fr)return err("Вы уже друзья",409);
      const reverse=await env.DB.prepare("SELECT id FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'").bind(target,user.id).first();if(reverse){await env.DB.prepare("UPDATE friend_requests SET status='accepted',updated_at=? WHERE id=?").bind(Date.now(),reverse.id).run();await env.DB.prepare("INSERT OR IGNORE INTO friendships(id,user_a,user_b,created_at) VALUES (?,?,?,?)").bind(randomToken(12),a,b,Date.now()).run();return json({ok:true,accepted:true});}
      const prior=await env.DB.prepare("SELECT id FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'").bind(user.id,target).first();if(prior)return err("Заявка уже отправлена",409);
      await env.DB.prepare("INSERT INTO friend_requests(id,from_user,to_user,status,created_at,updated_at) VALUES (?,?,?,'pending',?,?)").bind(randomToken(12),user.id,target,Date.now(),Date.now()).run();return json({ok:true});
    }
    if(p==="/api/friends/respond"&&method==="POST"){
      const d=await body(request),id=String(d?.requestId||""),accept=!!d?.accept;const fr=await env.DB.prepare("SELECT id,from_user,to_user FROM friend_requests WHERE id=? AND to_user=? AND status='pending'").bind(id,user.id).first();if(!fr)return err("Заявка не найдена",404);
      await env.DB.prepare("UPDATE friend_requests SET status=?,updated_at=? WHERE id=?").bind(accept?"accepted":"rejected",Date.now(),id).run();if(accept){const a=fr.from_user<fr.to_user?fr.from_user:fr.to_user,b=fr.from_user<fr.to_user?fr.to_user:fr.from_user;await env.DB.prepare("INSERT OR IGNORE INTO friendships(id,user_a,user_b,created_at) VALUES (?,?,?,?)").bind(randomToken(12),a,b,Date.now()).run();}return json({ok:true});
    }
    if(p.startsWith("/api/friends/")&&method==="DELETE"){
      const target=decodeURIComponent(p.slice("/api/friends/".length));if(!target)return err("Не указан друг");const a=user.id<target?user.id:target,b=user.id<target?target:user.id;await env.DB.prepare("DELETE FROM friendships WHERE user_a=? AND user_b=?").bind(a,b).run();await env.DB.prepare("UPDATE friend_requests SET status='removed',updated_at=? WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)").bind(Date.now(),user.id,target,target,user.id).run();return json({ok:true});
    }
    if(p==="/api/invites"&&method==="GET"){
      const r=await env.DB.prepare(`SELECT i.id,i.room_code,i.created_at,i.expires_at,u.id AS from_id,u.username AS from_name,u.avatar AS from_avatar FROM game_invites i JOIN users u ON u.id=i.from_user WHERE i.to_user=? AND i.status='pending' AND i.expires_at>? ORDER BY i.created_at DESC LIMIT 30`).bind(user.id,Date.now()).all();return json({invites:r.results||[]});
    }
    if(p==="/api/invites"&&method==="POST"){
      const d=await body(request),friendId=String(d?.friendId||""),room=String(d?.room||"").toUpperCase().replace(/[^A-Z0-9]/g,"");if(!friendId||room.length<6||room.length>12)return err("Нужен друг и действующий код комнаты");const a=user.id<friendId?user.id:friendId,b=user.id<friendId?friendId:user.id;const friendship=await env.DB.prepare("SELECT id FROM friendships WHERE user_a=? AND user_b=?").bind(a,b).first();if(!friendship)return err("Приглашать можно только друзей",403);const now=Date.now();await env.DB.prepare("INSERT INTO game_invites(id,from_user,to_user,room_code,status,created_at,expires_at) VALUES (?,?,?,?,'pending',?,?)").bind(randomToken(12),user.id,friendId,room,now,now+15*60*1000).run();return json({ok:true});
    }
    if(p==="/api/invites/respond"&&method==="POST"){
      const d=await body(request),id=String(d?.inviteId||""),accept=!!d?.accept;const invite=await env.DB.prepare("SELECT id,room_code FROM game_invites WHERE id=? AND to_user=? AND status='pending' AND expires_at>?").bind(id,user.id,Date.now()).first();if(!invite)return err("Приглашение истекло или не найдено",404);await env.DB.prepare("UPDATE game_invites SET status=? WHERE id=?").bind(accept?"accepted":"rejected",id).run();return json({ok:true,room:accept?invite.room_code:null});
    }
    return err("Не найден API-маршрут",404);
  }
  return null;
}


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
 const user=await currentUser(request,env);if(!user)return v2err("Нужно войти в аккаунт",401);
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
   const d=await body(request);if(!d?.payload||!["controls","interface","lobby","music","profile"].includes(d.payload.type))return v2err("Неизвестный тип конфигурации");
   const name=String(d.name||"Моя конфигурация").trim().slice(0,80)||"Моя конфигурация",payload=JSON.stringify(d.payload);
   if(payload.length>1_000_000)return v2err("Конфигурация больше 1 МБ. Большие медиафайлы загружай отдельно.",413);
   let code=null;for(let i=0;i<8;i++){const candidate=v2code();if(!await env.DB.prepare("SELECT code FROM shared_configs WHERE code=?").bind(candidate).first()){code=candidate;break;}}
   if(!code)return v2err("Не удалось создать код",503);
   const now=Date.now();await env.DB.prepare("INSERT INTO shared_configs(code,owner_id,config_type,name,payload_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)").bind(code,user.id,d.payload.type,name,payload,now,now).run();
   return v2json({ok:true,code,name,createdAt:now},201);
 }
 const cfg=path.match(/^\/api\/v2\/configs\/([A-Z]{6,32})$/);
 if(cfg&&method==="GET"){
   const r=await env.DB.prepare("SELECT code,config_type,name,payload_json,created_at FROM shared_configs WHERE code=?").bind(cfg[1]).first();
   if(!r)return v2err("Конфигурация не найдена",404);
   await env.DB.prepare("UPDATE shared_configs SET downloads=downloads+1 WHERE code=?").bind(cfg[1]).run();
   return v2json({code:r.code,type:r.config_type,name:r.name,payload:JSON.parse(r.payload_json),createdAt:r.created_at});
 }
 if(cfg&&method==="DELETE"){
   const r=await env.DB.prepare("DELETE FROM shared_configs WHERE code=? AND owner_id=?").bind(cfg[1],user.id).run();
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS,PATCH,DELETE","Access-Control-Allow-Headers":"Content-Type,Authorization,X-Asset-Name","Access-Control-Max-Age":"86400"}});
    if(url.pathname.startsWith("/api/v2/")){try{return await v2api(request,env,url)}catch(e){console.error("stage33 API error",e);return v2err("Внутренняя ошибка облачного API",500)}}
    if(url.pathname.startsWith("/api/auth/")||url.pathname==="/api/me"||url.pathname.startsWith("/api/profile")||url.pathname.startsWith("/api/friends")||url.pathname.startsWith("/api/users")||url.pathname.startsWith("/api/invites")||url.pathname==="/api/presence"||url.pathname==="/api/health"){if(!env.DB)return err("D1 не настроена. Выполни миграцию базы данных.",503);try{const response=await api(request,env,url);if(response)return response;}catch(e){console.error("API error",e);return err("Внутренняя ошибка API",500);}}
    if (url.pathname === "/" && request.method === "GET") return new Response("zomb Worker is running (accounts + WebRTC signaling). Open the game HTML separately.",{headers:{"Content-Type":"text/plain; charset=utf-8"}});
    if (url.pathname === "/api/room" && request.method === "POST") {
      let code = newRoomCode(); const id = env.ROOMS.idFromName(code); await env.ROOMS.get(id).fetch("https://room.internal/init",{method:"POST"}); return json({room:code});
    }
    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("Expected WebSocket",{status:426});
      const room=(url.searchParams.get("room")||"").toUpperCase().replace(/[^A-Z0-9]/g,"");if(room.length<6||room.length>12)return new Response("Invalid room code",{status:400});
      const id=env.ROOMS.idFromName(room);return env.ROOMS.get(id).fetch(request);
    }
    return err("Not found",404);
  }
};

export class Room {
  constructor(ctx,env){this.ctx=ctx;this.env=env;this.host=null;this.guests=new Map();this.clients=new Map();this.nextPeer=0;}
  async fetch(request){const url=new URL(request.url);if(url.pathname==="/init")return new Response("ok");if(request.headers.get("Upgrade")?.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:426});
    const role=url.searchParams.get("role"),name=safeName(url.searchParams.get("name")||(role==="host"?"Хост":"Игрок"));if(role!=="host"&&role!=="guest")return new Response("Invalid role",{status:400});if(role==="host"&&this.host)return new Response("Room already has a host",{status:409});if(role==="guest"&&!this.host)return new Response("Host is not connected yet",{status:409});if(role==="guest"&&this.guests.size>=15)return new Response("Room is full",{status:409});
    const pair=new WebSocketPair(),client=pair[0],server=pair[1];server.accept();const peerId=role==="guest"?"P"+(++this.nextPeer):"host",meta={role,name,peerId};this.clients.set(server,meta);if(role==="host")this.host=server;else this.guests.set(peerId,server);server.addEventListener("message",ev=>this.onMessage(server,ev.data));server.addEventListener("close",()=>this.onClose(server));server.addEventListener("error",()=>this.onClose(server));send(server,{t:"sig:ready",role,peerId,room:url.searchParams.get("room")||""});if(role==="guest")send(this.host,{t:"peer:join",peerId,name});return new Response(null,{status:101,webSocket:client});
  }
  onMessage(ws,raw){const meta=this.clients.get(ws);if(!meta)return;let m;try{m=JSON.parse(typeof raw==="string"?raw:new TextDecoder().decode(raw));}catch{return;}if(m.t!=="signal"||!m.data||typeof m.data.type!=="string")return;if(meta.role==="host"){const guest=this.guests.get(String(m.to||""));if(guest)send(guest,{t:"signal",from:"host",data:m.data});}else if(m.to==="host"&&this.host)send(this.host,{t:"signal",from:meta.peerId,data:m.data});}
  onClose(ws){const meta=this.clients.get(ws);if(!meta)return;this.clients.delete(ws);if(meta.role==="host"){this.host=null;for(const [,g] of this.guests){send(g,{t:"err",msg:"Хост отключился. Комната закрыта."});try{g.close(1001,"Host disconnected");}catch{}}this.guests.clear();}else{this.guests.delete(meta.peerId);if(this.host)send(this.host,{t:"peer:left",peerId:meta.peerId,name:meta.name});}}
}
function send(ws,obj){try{if(ws&&ws.readyState===1)ws.send(JSON.stringify(obj));}catch{}}
