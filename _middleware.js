// _middleware.js
// Cloudflare Pages Middleware — IP / 国家 黑名单 + 访问日志
// 文档：https://developers.cloudflare.com/pages/platform/functions/middleware/

// ============ 配置区 ============

// 单个 IP 黑名单
const BLOCKED_IPS = new Set([
  // '1.2.3.4',
  // '5.6.7.8',
]);

// IP 段黑名单（前缀匹配，封一整段）
const BLOCKED_PREFIXES = [
  // '10.0.0.',    // 封 10.0.0.0 - 10.0.0.255
  // '192.168.1.',
];

// 国家黑名单（ISO 两位代码，留空=不启用）
const BLOCKED_COUNTRIES = new Set([
  // 'XX',
]);

// 封禁页面
const BLOCK_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>访问受限</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fafafa;color:#333}
.card{text-align:center;padding:40px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:400px}
h1{font-size:48px;margin:0 0 16px;color:#e74c3c}
p{margin:0;line-height:1.6;color:#666}
</style></head>
<body><div class="card"><h1>403</h1>
<p>抱歉，您的访问已被限制。</p>
<p>如有疑问请联系站点管理员。</p>
</div></body></html>`;

// ============ 逻辑区 ============

function isBlocked(ip, country) {
  if (ip && BLOCKED_IPS.has(ip)) return true;
  if (ip) {
    for (const prefix of BLOCKED_PREFIXES) {
      if (ip.startsWith(prefix)) return true;
    }
  }
  if (country && BLOCKED_COUNTRIES.has(country)) return true;
  return false;
}

export async function onRequest(context) {
  const { request, env } = context;

  const ip =
    request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() ||
    '';
  const country = request.cf?.country || '';
  const ua = request.headers.get('User-Agent') || '';
  const url = new URL(request.url);
  const path = url.pathname;

  // ---- 管理页面：/admin ----
  if (path === '/admin' || path === '/admin/') {
    return new Response(ADMIN_HTML, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // ---- 管理接口：/admin/api/visits ----
  if (path === '/admin/api/visits') {
    // 简单密钥保护，部署后在 Pages Settings → Environment Variables 设 ADMIN_KEY
    const authKey = url.searchParams.get('key') || '';
    if (env.ADMIN_KEY && authKey !== env.ADMIN_KEY) {
      return new Response('Unauthorized', { status: 401 });
    }

    if (request.method === 'DELETE') {
      // 清空日志
      await env.VISIT_LOG?.put('visits', '[]');
      return jsonResponse({ ok: true, message: '已清空' });
    }

    // GET：读取日志
    const raw = await env.VISIT_LOG?.get('visits') || '[]';
    let visits = [];
    try { visits = JSON.parse(raw); } catch { visits = []; }
    return jsonResponse({ visits, count: visits.length });
  }

  // ---- 访问日志记录 ----
  if (env.VISIT_LOG) {
    try {
      const raw = await env.VISIT_LOG.get('visits') || '[]';
      let visits = [];
      try { visits = JSON.parse(raw); } catch { visits = []; }
      visits.unshift({
        ip,
        country,
        ua: ua.substring(0, 120),
        path,
        time: new Date().toISOString(),
      });
      // 只保留最近 500 条
      if (visits.length > 500) visits = visits.slice(0, 500);
      await env.VISIT_LOG.put('visits', JSON.stringify(visits));
    } catch {
      // KV 写入失败不影响正常访问
    }
  }

  // ---- 黑名单检查 ----
  if (isBlocked(ip, country)) {
    return new Response(BLOCK_HTML, {
      status: 403,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  return await context.next();
}

function jsonResponse(data) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

// ============ 管理页面 HTML ============
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>访问日志管理</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,'Segoe UI',sans-serif;background:#f5f5f5;color:#333;padding:20px}
.container{max-width:900px;margin:0 auto}
h1{font-size:24px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.stats{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:#fff;padding:16px 24px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}
.stat .num{font-size:28px;font-weight:700;color:#2563eb}
.stat .label{font-size:13px;color:#999;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}
th{background:#f0f0f0;padding:10px 12px;text-align:left;font-size:13px;color:#666;white-space:nowrap}
td{padding:10px 12px;border-top:1px solid #eee;font-size:13px;word-break:break-all}
.ip{font-family:monospace;font-weight:600}
.flag{font-size:18px}
.btn{background:#e74c3c;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px;margin-left:auto}
.btn:hover{background:#c0392b}
.empty{text-align:center;padding:40px;color:#999}
.auth-box{background:#fff;padding:24px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;margin-top:40px}
.auth-box input{padding:8px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;width:240px}
.auth-box button{padding:8px 16px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;margin-left:8px}
.auth-box button:hover{background:#1d4ed8}
.actions{display:flex;align-items:center;margin-bottom:16px}
.refresh{background:#2563eb;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px}
</style></head>
<body><div class="container">
<h1>📊 访问日志</h1>
<div id="auth" class="auth-box" style="display:none">
<p style="margin-bottom:12px">输入管理密钥查看访问日志</p>
<input id="keyInput" type="password" placeholder="Admin Key">
<button onclick="load()">查看</button>
</div>
<div id="content" style="display:none">
<div class="stats" id="stats"></div>
<div class="actions">
<button class="refresh" onclick="load()">刷新</button>
<button class="btn" onclick="clearLogs()">清空日志</button>
</div>
<table id="table"></table>
</div>
</div>
<script>
let savedKey='';
function load(){
  const keyInput=document.getElementById('keyInput');
  if(keyInput.value)savedKey=keyInput.value;
  if(!savedKey){document.getElementById('auth').style.display='block';return;}
  fetch('/admin/api/visits?key='+encodeURIComponent(savedKey))
    .then(r=>r.ok?r.json():Promise.reject(r))
    .then(d=>{
      document.getElementById('auth').style.display='none';
      document.getElementById('content').style.display='block';
      const visits=d.visits||[];
      document.getElementById('stats').innerHTML=
        '<div class="stat"><div class="num">'+d.count+'</div><div class="label">总访问</div></div>'+
        '<div class="stat"><div class="num">'+countUnique(visits)+'</div><div class="label">独立IP</div></div>'+
        '<div class="stat"><div class="num">'+todayCount(visits)+'</div><div class="label">今日</div></div>';
      if(visits.length===0){
        document.getElementById('table').innerHTML='<tbody><tr><td colspan="5" class="empty">暂无访问记录</td></tr></tbody>';
        return;
      }
      let html='<thead><tr><th>时间</th><th>IP</th><th>地区</th><th>路径</th><th>UA</th></tr></thead><tbody>';
      visits.forEach(v=>{
        const t=v.time?new Date(v.time).toLocaleString('zh-CN'):'';
        html+='<tr><td>'+t+'</td><td class="ip">'+v.ip+'</td><td>'+v.country+'</td><td>'+v.path+'</td><td style="color:#999;max-width:200px;overflow:hidden;text-overflow:ellipsis">'+v.ua+'</td></tr>';
      });
      html+='</tbody>';
      document.getElementById('table').innerHTML=html;
    })
    .catch(()=>{
      alert('密钥错误或请求失败');
      document.getElementById('auth').style.display='block';
      document.getElementById('content').style.display='none';
    });
}
function countUnique(visits){return new Set(visits.map(v=>v.ip)).size;}
function todayCount(visits){
  const today=new Date().toDateString();
  return visits.filter(v=>v.time&&new Date(v.time).toDateString()===today).length;
}
function clearLogs(){
  if(!confirm('确认清空所有访问日志？'))return;
  fetch('/admin/api/visits?key='+encodeURIComponent(savedKey),{method:'DELETE'})
    .then(r=>r.json())
    .then(()=>load());
}
load();
</script>
</body></html>`;
