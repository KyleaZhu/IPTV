// 江西九江频道
// 数据源 https://app.jjntv.cn/webDetails/live/tvLive?tenantId=314&id=40
//
// 用法（只认这两种写法，其余路径一律 404）：
//   /jj1         -> 302 跳到带签名的 hlsUrl，起播一次，24h 后失效
//   /jj1.m3u8    -> 代理播放列表：每次实时取新签名地址并改写分片为绝对链接，
//                   分片由播放器直连 quklive，长期播放不会因 auth_key 过期断流
//
// 部署：wrangler.toml 里 main 指向本文件，npx wrangler deploy

const TENANT = '314';
const SID = '111111111111111111111111';
const KEY = 'FR*r!isE5W';

const URL_TTL = 300;           // 签名地址缓存秒数（地址本身 24h 有效，缓存 5 分钟很安全）

const CH = {
  jj1: '1768529286203024', // 九江一套 (现网频道 id 40)
  jj2: '1776821035295363', // 九江二套 (现网频道 id 41)
  jj3: '1776821070594049', // 九江三套 (现网频道 id 42)
};

const toHex = buf => [...new Uint8Array(buf)]
  .map(b => b.toString(16).padStart(2, '0')).join('');

// 签名规则：sha256(path && sessionId && requestId && timestamp && key && tenantId)
// path 不含 query，timestamp 为毫秒
async function playUrl(activityId, minutes = 1440) {
  const path = '/api/quklive/generateTempPlayUrl';
  const ts = String(Date.now());
  const rid = crypto.randomUUID();
  const sig = toHex(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(`${path}&&${SID}&&${rid}&&${ts}&&${KEY}&&${TENANT}`)));

  const res = await fetch(
    `https://app.jjntv.cn${path}?activityId=${activityId}&minutes=${minutes}`, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
      'X-Tenant-Id': TENANT,
      'X-SESSION-ID': SID,
      'X-REQUEST-ID': rid,
      'X-TIMESTAMP': ts,
      'X-SIGNATURE': sig,
    },
  });

  // 上游异常时可能返回 HTML 挑战页，直接 .json() 会抛 SyntaxError 并把真实状态吞掉
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 非 JSON，交给下面统一报错 */ }
  if (!res.ok || !json || json.code !== 0) {
    throw new Error(`upstream ${res.status} code=${json ? json.code : 'n/a'} ${text.slice(0, 120)}`);
  }
  return json.data?.hlsUrl || '';
}

// 带缓存的取流地址：缓存命中就省掉一次跨境签名请求（playlist 每 7s 刷新一次，收益明显）
async function cachedPlayUrl(aid, ctx) {
  const cache = caches.default;
  const key = new Request(`https://jjtv.internal/url/${aid}`);

  const hit = await cache.match(key);
  if (hit) return await hit.text();

  const url = await playUrl(aid);
  if (url) {
    const toCache = new Response(url, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': `max-age=${URL_TTL}`,
      },
    });
    ctx.waitUntil(cache.put(key, toCache).catch(() => {}));
  }
  return url;
}

export default {
  async fetch(req, env, ctx) {
    // 只接受 /jjN 与 /jjN.m3u8；不设默认频道，路径写错立刻暴露成 404
    const m = new URL(req.url).pathname.match(/^\/([A-Za-z0-9]+)(\.m3u8)?$/);
    if (!m) return new Response('not found', { status: 404 });

    const id = m[1];
    const asPlaylist = !!m[2];
    const aid = CH[id];
    if (!aid) return new Response('unknown id: ' + id, { status: 404 });

    let target = '';
    try {
      target = await cachedPlayUrl(aid, ctx);
    } catch (e) {
      return new Response('sign fail: ' + e.message, { status: 502 });
    }
    if (!target) return new Response('upstream failed', { status: 502 });

    // A 模式：直接 302
    if (!asPlaylist) {
      return new Response(null, {
        status: 302,
        headers: { Location: target, 'Cache-Control': 'no-store' },
      });
    }

    // B 模式：代理播放列表，分片地址补成绝对链接
    // 这里的异常必须自己接住：超出 fetch 处理器会变成 500 + Error 1101，播放器看不出原因
    let body;
    try {
      const r = await fetch(target, { headers: { 'User-Agent': 'Mozilla/5.0' } });
      if (!r.ok) {
        return new Response('playlist fetch failed: ' + r.status, { status: 502 });
      }
      body = (await r.text())
        .replace(/^(?!#)(\S+)$/gm, line => new URL(line, target).href);
    } catch (e) {
      return new Response('playlist error: ' + e.message, { status: 502 });
    }

    return new Response(body, {
      headers: {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Cache-Control': 'no-store',
      },
    });
  },
};
