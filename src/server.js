import express from 'express';
import { promises as fs } from 'fs';
import fsSync from 'fs';
import path from 'path';
import { setTimeout as wait } from 'timers/promises';
import 'dotenv/config';
import { getSupabase } from './supabaseClient.js';

const app = express();
const PORT = process.env.PORT || 3001;

// OpenSea API key must be provided via environment (OPENSEA_API_KEY). No hardcoded fallback in production.

// Basic CORS (adjust as needed). Allows common headers and credentials if needed.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Admin-Token, X-Admin');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (_req, res) => res.json({ ok: true }));

// Helper: require admin token in production
function requireAdminInProd(req, res) {
  const isProd = (process.env.VERCEL || process.env.NODE_ENV === 'production');
  if (!isProd) return true;
  const token = req.headers['x-admin-token'];
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    res.status(401).json({ ok: false, error: 'Unauthorized: missing or invalid X-Admin-Token' });
    return false;
  }
  return true;
}

// Simple Sybil game endpoints
// GET /api/games/sybil/start -> starts a session (stateless placeholder)
app.get('/api/games/sybil/start', (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const now = new Date().toISOString();
    const phase = { phase1: 0.5, phase2: 0.5 };
    return res.status(200).json({ ok: true, game: 'sybil', action: 'start', phase, ip, startedAt: now });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// GET /xps-ranked/sync-tiers
// Reads output/concat.json (or ?file=) and updates user_profile_stats.tier for each user_id found.
// Security: require X-Admin-Token header to match process.env.ADMIN_TOKEN in production.
app.get('/xps-ranked/sync-tiers', async (req, res) => {
  try {
    const adminToken = req.headers['x-admin-token'];
    const isProd = (process.env.VERCEL || process.env.NODE_ENV === 'production');
    if (isProd) {
      if (!process.env.ADMIN_TOKEN || adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ ok: false, error: 'Unauthorized: missing or invalid X-Admin-Token' });
      }
    }

    const filePath = req.query.file ? String(req.query.file) : path.join(process.cwd(), 'output', 'concat.json');
    const dryRun = String(req.query.dryRun ?? 'false').toLowerCase() === 'true';

    async function readJsonSafe(file) {
      try {
        const txt = await fs.readFile(file, 'utf8');
        return JSON.parse(txt);
      } catch (e) {
        return undefined;
      }
    }
    const data = await readJsonSafe(filePath);
    if (!data) return res.status(400).json({ ok: false, error: 'Could not read or parse JSON file', filePath });

    const arr = Array.isArray(data) ? data : (Array.isArray(data?.results) ? data.results : []);
    if (!Array.isArray(arr) || arr.length === 0) return res.json({ ok: true, filePath, totalItems: 0, uniqueUsers: 0, updated: 0, skipped: 0, dryRun });

    // Build per-user tier frequency and choose the most frequent tier
    const tierCountsByUser = new Map(); // userId:number -> Map(tier:number -> count)
    let itemsScanned = 0;
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const idInfo = getIdFromObject(item, 'user_id');
      if (!idInfo) continue;
      const uidNum = Number(idInfo.value);
      if (!Number.isFinite(uidNum) || uidNum <= 0) continue;
      const t = toNumber(item.tier);
      if (!Number.isFinite(t)) continue;
      const ti = Math.trunc(t);
      if (!tierCountsByUser.has(uidNum)) tierCountsByUser.set(uidNum, new Map());
      const m = tierCountsByUser.get(uidNum);
      m.set(ti, (m.get(ti) || 0) + 1);
      itemsScanned++;
    }

    // Decide final tier per user: most frequent; tie-breaker -> largest tier number
    const finalTierByUser = new Map();
    for (const [uid, m] of tierCountsByUser.entries()) {
      let bestTier = null;
      let bestCount = -1;
      for (const [tierVal, cnt] of m.entries()) {
        if (cnt > bestCount || (cnt === bestCount && tierVal > (bestTier ?? -Infinity))) {
          bestTier = tierVal;
          bestCount = cnt;
        }
      }
      if (bestTier != null) finalTierByUser.set(uid, bestTier);
    }

    const sb = getSupabase();
    let updated = 0;
    let failed = 0;
    const errors = [];

    async function updateOne(uid, tier) {
      try {
        if (dryRun) return true;
        const r = await sb.from('user_profile_stats').update({ tier }).eq('user_id', uid);
        if (r.error) throw new Error(r.error.message || 'Supabase update error');
        return true;
      } catch (e) {
        errors.push({ uid, tier, error: e?.message || String(e) });
        return false;
      }
    }

    // Concurrency control
    const entries = Array.from(finalTierByUser.entries());
    const concurrency = Number(req.query.concurrency ?? 10);
    let i = 0;
    async function nextBatch() {
      const batch = [];
      for (let k = 0; k < concurrency && i < entries.length; k++, i++) {
        const [uid, tier] = entries[i];
        batch.push(updateOne(uid, tier).then((ok) => { if (ok) updated++; else failed++; }));
      }
      await Promise.all(batch);
      if (i < entries.length) await nextBatch();
    }
    await nextBatch();

    return res.json({
      ok: true,
      filePath,
      dryRun,
      totalItems: arr.length,
      itemsWithTier: itemsScanned,
      uniqueUsers: finalTierByUser.size,
      updated,
      failed,
      errorsSample: errors.slice(0, 10),
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// Helper: sanitize and prepare headers for upstream call
function buildUpstreamHeaders(reqHeaders) {
  const drop = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade', 'via', 'x-forwarded-for']);
  const h = {}; 
  for (const [k, v] of Object.entries(reqHeaders || {})) {
    const key = String(k).toLowerCase();
    if (!drop.has(key) && v !== undefined && v !== null) h[key] = v;
  }
  //
  // Provide some sensible defaults if caller didn't set them
  h['accept'] ||= 'application/json, text/plain, */*';
  h['accept-encoding'] ||= 'gzip, deflate, br, zstd';
  h['accept-language'] ||= 'en-US,en;q=0.8';
  h['user-agent'] ||= 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';
  h['origin'] ||= 'https://common.xyz';
  h['referer'] ||= 'https://common.xyz/leaderboard';
  return h;
}

// Common Checker helpers (top-level)
const parsePct = (val, defVal) => {
  if (val == null) return defVal;
  const n = Number(String(val).replace(/[^0-9.+-]/g, ''));
  return Number.isFinite(n) ? n : defVal;
};
const fmtPct = (x) => (typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('en-US', { maximumFractionDigits: 2 }) + '%' : '—');
const filterUserMsgs = (arr) => {
  const HIDE = [
    /^(no )?common credentials/i,
    /^common api error/i,
    /^no wallet address found/i,
  ];
  return (Array.isArray(arr) ? arr : []).filter((m) => !HIDE.some((rx) => rx.test(String(m))));
};

// Simple in-memory rate limiting (best-effort; resets per process)
const RATE_LIMITS = {
  global: { windowMs: 60_000, max: 120 },
  write: { windowMs: 60_000, max: 20 },
};
const rateStore = new Map(); // key -> { resetAt, remaining }
function checkLimit(key, conf) {
  const now = Date.now();
  let st = rateStore.get(key);
  if (!st || now >= st.resetAt) {
    st = { resetAt: now + conf.windowMs, remaining: conf.max };
  }
  if (st.remaining <= 0) {
    rateStore.set(key, st);
    return { allowed: false, retryAfter: Math.ceil((st.resetAt - now) / 1000) };
  }
  st.remaining -= 1;
  rateStore.set(key, st);
  return { allowed: true, remaining: st.remaining, resetAt: st.resetAt };
}
function limiter(conf) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const key = `${conf.max}:${ip}`;
    const resLimit = checkLimit(key, conf);
    if (!resLimit.allowed) {
      res.setHeader('Retry-After', String(resLimit.retryAfter));
      return res.status(429).json({ error: 'Too many requests', retryAfter: resLimit.retryAfter });
    }
    next();
  };
}

// Apply global limiter to all routes
app.use(limiter(RATE_LIMITS.global));

// Helper: read auth/cookie from headers or query params
function getAuthCookieFromRequest(req) {
  // Headers are lower-cased by Express
  const hdrAuth = req.headers['authorization'];
  const hdrCookie = req.headers['cookie'];
  const q = req.query || {};
  // Accept query fallbacks like ?authorization=...&cookie=...
  const qAuth = typeof q.authorization === 'string' ? q.authorization : undefined;
  const qCookie = typeof q.cookie === 'string' ? q.cookie : undefined;
  return {
    authorization: hdrAuth || qAuth,
    cookie: hdrCookie || qCookie,
  };
}

// GET /xps-ranked/save
// Reads Authorization and Cookie from incoming headers, fetches upstream once, and writes body to output/leaderboard.txt
app.get('/xps-ranked/save', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const limit = Number(req.query.limit ?? 50) || 50; // Default limit for pagination
    const direction = String(req.query.direction ?? 'forward');
    const cursorRaw = req.query.cursor;

    const payload = { limit, direction };
    if (cursorRaw !== undefined && cursorRaw !== '') {
      const curNum = Number(cursorRaw);
      if (!Number.isNaN(curNum)) payload.cursor = curNum;
    }
    const inputParam = JSON.stringify(payload);
    const upstreamUrl = 'https://common.xyz/api/internal/trpc/user.getXpsRanked?input=' + encodeURIComponent(inputParam);

  const headersOut = buildUpstreamHeaders(req.headers);
  if (auth) headersOut['authorization'] = auth;
  if (cookie) headersOut['cookie'] = cookie;

    const resp = await fetch(upstreamUrl, { method: 'GET', headers: headersOut });
    const text = await resp.text();

    const outDir = path.join(process.cwd(), 'output');
    await fs.mkdir(outDir, { recursive: true });
    const outPath = path.join(outDir, 'leaderboard.txt');
    await fs.writeFile(outPath, text, 'utf8');

    return res.status(resp.status).json({ ok: resp.ok, status: resp.status, saved: outPath });
  } catch (err) {
    return res.status(500).json({ error: 'Save failure', message: err?.message || String(err) });
  }
});

// Helper: recursively find the maximum array length within a JSON structure
function findMaxArrayLen(node) {
  let maxLen = 0;
  const stack = [node];
  while (stack.length) {
    const cur = stack.pop();
    if (Array.isArray(cur)) {
      if (cur.length > maxLen) maxLen = cur.length;
      for (const v of cur) stack.push(v);
    } else if (cur && typeof cur === 'object') {
      for (const v of Object.values(cur)) stack.push(v);
    }
  }
  return maxLen;
}

// GET /xps-ranked/save-all
// Iterates cursor from start (default 1) upwards until an empty page is detected or max requests reached.
// Saves each page response body to output/pages/page_<cursor>.txt and returns a summary.
app.get('/xps-ranked/save-all', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const start = Number(req.query.start ?? 1) || 1; // Starting cursor for pagination
    const limit = Number(req.query.limit ?? 50) || 50;
    const direction = String(req.query.direction ?? 'forward');
  // Increase default page scan and hard cap; allow overrides via env or query
  const maxDefault = Number(process.env.SAVE_ALL_MAX_DEFAULT ?? 5000) || 5000; // previous default was 1000
  const hardCap = Math.max(1000, Number(process.env.SAVE_ALL_HARD_CAP ?? 100000) || 100000); // previous cap was 10000
  const max = Math.min(Number(req.query.max ?? maxDefault) || maxDefault, hardCap);
    const delayMs = Math.max(0, Number(req.query.delayMs ?? 0) || 0);
    const stopOnEmpty = String(req.query.stopOnEmpty ?? 'true').toLowerCase() !== 'false';

    const outDir = path.join(process.cwd(), 'output', 'pages');
    await fs.mkdir(outDir, { recursive: true });

  const headersOut = buildUpstreamHeaders(req.headers);
  if (auth) headersOut['authorization'] = auth;
  if (cookie) headersOut['cookie'] = cookie;

    let pages = 0;
    let lastCursor = start - 1;
    let stoppedBecause = 'maxReached';
    for (let cursor = start; cursor < start + max; cursor++) {
      const payload = { limit, direction, cursor };
      const inputParam = JSON.stringify(payload);
      const upstreamUrl = 'https://common.xyz/api/internal/trpc/user.getXpsRanked?input=' + encodeURIComponent(inputParam);
  const resp = await fetch(upstreamUrl, { method: 'GET', headers: headersOut });
      const text = await resp.text();

      const pagePathBase = path.join(outDir, `page_${cursor}`);
      const filePath = pagePathBase + (resp.ok ? '.txt' : '.error.txt');
      await fs.writeFile(filePath, text, 'utf8');

      if (!resp.ok) {
        stoppedBecause = `httpError:${resp.status}`;
        lastCursor = cursor;
        break;
      }

      // Try to detect emptiness
      let isEmpty = false;
      try {
        const json = JSON.parse(text);
        const maxArrLen = findMaxArrayLen(json);
        isEmpty = maxArrLen === 0;
      } catch {
        // If parsing fails, assume not empty so we keep going
        isEmpty = false;
      }

      pages++;
      lastCursor = cursor;

      if (stopOnEmpty && isEmpty) {
        stoppedBecause = 'emptyPage';
        break;
      }

      if (delayMs > 0) await wait(delayMs);
    }

    if (pages >= max && stoppedBecause === 'maxReached') {
      // No earlier break; reached the cap
      stoppedBecause = 'maxReached';
    }

    const summary = {
      ok: true,
      start,
      lastCursor,
      pagesSaved: pages,
      limit,
      direction,
      max,
      delayMs,
      stopOnEmpty,
      stoppedBecause,
      outputDir: outDir,
    };

    // Write a manifest for convenience
    try {
      await fs.writeFile(path.join(outDir, 'manifest.json'), JSON.stringify(summary, null, 2), 'utf8');
    } catch {}

    return res.json(summary);
  } catch (err) {
    return res.status(500).json({ error: 'Save-all failure', message: err?.message || String(err) });
  }
});

// Utility: parse a value into a finite number if possible
function toNumber(val) {
  if (typeof val === 'number' && Number.isFinite(val)) return val;
  if (typeof val === 'string') {
    const n = Number(val.replace(/[,\s]/g, ''));
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

// Utility: extract xp_points numeric value from an object
function getXpPointsFromObject(obj) {
  const keys = ['xp_points', 'xpPoints', 'xp'];
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) {
      const n = toNumber(obj[k]);
      if (n !== undefined) return { key: k, value: n };
    }
  }
  return undefined;
}

// Utility: find a plausible identifier key for deduplication
function getIdFromObject(obj, customKey) {
  const candidates = customKey
    ? [customKey]
    : [
        'user_id',
        'userId',
        'id',
        'user_name',
        'username',
        'handle',
        'profileId',
        'address',
        'wallet',
        'account',
        'slug',
      ];
  for (const k of candidates) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) {
      const v = obj[k];
      if (v !== null && v !== undefined) return { key: k, value: String(v) };
    }
  }
  return undefined;
}

// GET /xps-ranked/aggregate
// Scans output/pages (*.txt) files, extracts entries with an xp_points value and counts unique persons.
// Query params: dir (optional), idKey (optional), unique=true|false, includeErrors=false|true, limitFiles (number)
app.get('/xps-ranked/aggregate', async (req, res) => {
  try {
    const baseDir = req.query.dir ? String(req.query.dir) : path.join(process.cwd(), 'output', 'pages');
    const includeErrors = String(req.query.includeErrors ?? 'false').toLowerCase() === 'true';
    const unique = String(req.query.unique ?? 'true').toLowerCase() !== 'false';
    const idKey = req.query.idKey ? String(req.query.idKey) : undefined;
    const limitFiles = req.query.limitFiles ? Number(req.query.limitFiles) : undefined;

    const entries = await fs.readdir(baseDir);
    const pageFiles = entries
      .filter((f) => f.endsWith('.txt'))
      .filter((f) => includeErrors || !f.endsWith('.error.txt'))
      .filter((f) => f !== 'leaderboard.txt');

    const sortedFiles = pageFiles.slice().sort((a, b) => {
      // Sort by numeric cursor in filename if present
      const na = Number((a.match(/page_(\d+)/) || [])[1]);
      const nb = Number((b.match(/page_(\d+)/) || [])[1]);
      if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
      return a.localeCompare(b);
    });

    const filesToRead = typeof limitFiles === 'number' && limitFiles > 0 ? sortedFiles.slice(0, limitFiles) : sortedFiles;

    let filesProcessed = 0;
    let filesFailed = 0;
  let totalXp = 0;
  let entriesCount = 0;
    const uniqueIds = new Set();
    let dedupeKeyUsed = idKey || null;

    for (const fname of filesToRead) {
      const fullPath = path.join(baseDir, fname);
      try {
        const text = await fs.readFile(fullPath, 'utf8');
        let data;
        try {
          data = JSON.parse(text);
        } catch {
          filesFailed++;
          continue;
        }

        // Traverse breadth-first to find objects with xp_points
        const queue = [data];
        while (queue.length) {
          const cur = queue.shift();
          if (!cur) continue;
          if (Array.isArray(cur)) {
            for (const v of cur) queue.push(v);
          } else if (typeof cur === 'object') {
            // Check this object
            const xp = getXpPointsFromObject(cur);
            if (xp) {
              entriesCount++;
              totalXp += xp.value;
              if (unique) {
                const idInfo = getIdFromObject(cur, idKey);
                if (idInfo) {
                  uniqueIds.add(`${idInfo.key}::${idInfo.value}`);
                  if (!dedupeKeyUsed) dedupeKeyUsed = idInfo.key;
                }
              }
            }
            // enqueue children
            for (const v of Object.values(cur)) queue.push(v);
          }
        }
        filesProcessed++;
      } catch {
        filesFailed++;
      }
    }

    const personCount = unique ? (uniqueIds.size || entriesCount) : entriesCount;

    const summary = {
      ok: true,
      dir: baseDir,
      filesProcessed,
      filesFailed,
      entriesWithXpPoints: entriesCount,
      personCount,
      totalXpPoints: totalXp,
      unique,
      dedupeKeyUsed,
    };

    // Persist a copy for convenience
    try {
      const outDir = path.join(process.cwd(), 'output');
      await fs.mkdir(outDir, { recursive: true });
      await fs.writeFile(path.join(outDir, 'aggregate.json'), JSON.stringify(summary, null, 2), 'utf8');
    } catch {}

    return res.json(summary);
  } catch (err) {
    return res.status(500).json({ error: 'Aggregate failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/concat
// Concatenates all .txt page files into a single text file.
// Query params: dir (default output/pages), includeErrors=false|true, outFile (default output/concat.txt)
app.get('/xps-ranked/concat', async (req, res) => {
  try {
    const baseDir = req.query.dir ? String(req.query.dir) : path.join(process.cwd(), 'output', 'pages');
    const includeErrors = String(req.query.includeErrors ?? 'false').toLowerCase() === 'true';
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'concat.txt');

    const files = (await fs.readdir(baseDir))
      .filter((f) => f.endsWith('.txt'))
      .filter((f) => includeErrors || !f.endsWith('.error.txt'))
      .sort((a, b) => {
        const na = Number((a.match(/page_(\d+)/) || [])[1]);
        const nb = Number((b.match(/page_(\d+)/) || [])[1]);
        if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
        return a.localeCompare(b);
      });

    // Stream-concat for memory efficiency
    const outputDir = path.dirname(outFile);
    await fs.mkdir(outputDir, { recursive: true });
    const chunks = [];
    for (const fname of files) {
      const content = await fs.readFile(path.join(baseDir, fname), 'utf8');
      chunks.push(`\n--- FILE: ${fname} ---\n`);
      chunks.push(content);
      chunks.push('\n');
    }
    await fs.writeFile(outFile, chunks.join(''), 'utf8');

    return res.json({ ok: true, files: files.length, outFile });
  } catch (err) {
    return res.status(500).json({ error: 'Concat failure', message: err?.message || String(err) });
  }
});

// Helpers for JSON concatenation
function getByPath(obj, pathStr) {
  if (!pathStr) return undefined;
  const parts = String(pathStr).split('.').filter(Boolean);
  let cur = obj;
  for (const p of parts) {
    if (!cur || typeof cur !== 'object' || !(p in cur)) return undefined;
    cur = cur[p];
  }
  return cur;
}

function findArrayInJson(data) {
  // If the whole document is an array
  if (Array.isArray(data)) return data;
  // BFS: prefer first non-empty array; fallback to the largest array seen
  let best = undefined;
  let bestLen = -1;
  const queue = [data];
  while (queue.length) {
    const cur = queue.shift();
    if (!cur) continue;
    if (Array.isArray(cur)) {
      if (cur.length > 0) return cur; // early return on first non-empty
      if (cur.length > bestLen) {
        best = cur;
        bestLen = cur.length;
      }
    } else if (typeof cur === 'object') {
      for (const v of Object.values(cur)) queue.push(v);
    }
  }
  return best || [];
}

// GET /xps-ranked/concat-json
// Merges JSON arrays from page files into a single JSON array file without file name markers.
// Query params: dir (default output/pages), includeErrors=false|true, outFile (default output/concat.json), arrayPath (dot path), limitFiles (number)
app.get('/xps-ranked/concat-json', async (req, res) => {
  try {
    const baseDir = req.query.dir ? String(req.query.dir) : path.join(process.cwd(), 'output', 'pages');
    const includeErrors = String(req.query.includeErrors ?? 'false').toLowerCase() === 'true';
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'concat.json');
    const arrayPath = req.query.arrayPath ? String(req.query.arrayPath) : undefined;
    const limitFiles = req.query.limitFiles ? Number(req.query.limitFiles) : undefined;

    const files = (await fs.readdir(baseDir))
      .filter((f) => f.endsWith('.txt'))
      .filter((f) => includeErrors || !f.endsWith('.error.txt'))
      .sort((a, b) => {
        const na = Number((a.match(/page_(\d+)/) || [])[1]);
        const nb = Number((b.match(/page_(\d+)/) || [])[1]);
        if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
        return a.localeCompare(b);
      });

    const readList = typeof limitFiles === 'number' && limitFiles > 0 ? files.slice(0, limitFiles) : files;

    await fs.mkdir(path.dirname(outFile), { recursive: true });
    const ws = fsSync.createWriteStream(outFile, { encoding: 'utf8' });
    let wroteAny = false;
    let filesProcessed = 0;
    let filesFailed = 0;
    let itemsWritten = 0;

    await new Promise(async (resolve, reject) => {
      ws.on('error', reject);
      ws.write('[');
      try {
        for (const fname of readList) {
          const fullPath = path.join(baseDir, fname);
          let text;
          try {
            text = await fs.readFile(fullPath, 'utf8');
          } catch {
            filesFailed++;
            continue;
          }
          let json;
          try {
            json = JSON.parse(text);
          } catch {
            filesFailed++;
            continue;
          }
          let arr;
          if (arrayPath) {
            const val = getByPath(json, arrayPath);
            arr = Array.isArray(val) ? val : undefined;
          }
          if (!arr) arr = findArrayInJson(json);
          if (!Array.isArray(arr)) arr = [];
          for (const item of arr) {
            if (wroteAny) ws.write(',');
            ws.write(JSON.stringify(item));
            wroteAny = true;
            itemsWritten++;
          }
          filesProcessed++;
        }
        ws.write(']');
        ws.end(resolve);
      } catch (e) {
        reject(e);
      }
    });

    return res.json({ ok: true, filesProcessed, filesFailed, itemsWritten, outFile });
  } catch (err) {
    return res.status(500).json({ error: 'Concat JSON failure', message: err?.message || String(err) });
  }
});

// Helper: scan entire JSON and return the maximum xp_points value found
function findMaxXpPoints(node) {
  let max = undefined;
  const stack = [node];
  while (stack.length) {
    const cur = stack.pop();
    if (!cur) continue;
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push(v);
    } else if (typeof cur === 'object') {
      const xp = getXpPointsFromObject(cur);
      if (xp && (max === undefined || xp.value > max)) max = xp.value;
      for (const v of Object.values(cur)) stack.push(v);
    }
  }
  return max;
}

// Helpers: extract activity counts from user profile JSON
function findMaxArrayLenByKeys(node, keys) {
  const keySet = new Set((keys || []).map((k) => String(k).toLowerCase()));
  let maxLen = 0;
  const stack = [node];
  while (stack.length) {
    const cur = stack.pop();
    if (!cur) continue;
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push(v);
    } else if (typeof cur === 'object') {
      for (const [k, v] of Object.entries(cur)) {
        if (Array.isArray(v)) {
          const lk = String(k).toLowerCase();
          if (keySet.has(lk)) {
            if (v.length > maxLen) maxLen = v.length;
          }
        }
        if (v && (typeof v === 'object')) stack.push(v);
      }
    }
  }
  return maxLen;
}

function findNumericMaxByKeys(node, keys) {
  const keySet = new Set((keys || []).map((k) => String(k).toLowerCase()));
  let maxVal = undefined;
  const stack = [node];
  while (stack.length) {
    const cur = stack.pop();
    if (!cur) continue;
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push(v);
    } else if (typeof cur === 'object') {
      for (const [k, v] of Object.entries(cur)) {
        const lk = String(k).toLowerCase();
        if (keySet.has(lk)) {
          const n = toNumber(v);
          if (n !== undefined) {
            if (maxVal === undefined || n > maxVal) maxVal = n;
          }
        }
        if (v && (typeof v === 'object')) stack.push(v);
      }
    }
  }
  return maxVal;
}

function computeProfileActivityCounts(json) {
  // Heuristics: prefer arrays named explicitly; take max length seen to avoid double counting mirrors
  const addresses = findMaxArrayLenByKeys(json, ['addresses', 'addressList', 'wallets', 'accounts']);
  const threads = findMaxArrayLenByKeys(json, ['threads', 'userThreads', 'createdThreads']);
  const comments = findMaxArrayLenByKeys(json, ['comments', 'userComments']);
  const commentThreads = findMaxArrayLenByKeys(json, ['commentThreads', 'commentedThreads']);
  const totalUpvotes = findNumericMaxByKeys(json, ['totalUpvotes', 'total_upvotes']);
  return {
    addresses: Number.isFinite(addresses) ? addresses : 0,
    threads: Number.isFinite(threads) ? threads : 0,
    comments: Number.isFinite(comments) ? comments : 0,
    totalUpvotes: totalUpvotes ?? null,
    commentThreads: Number.isFinite(commentThreads) ? commentThreads : 0,
  };
}

// Extract profile meta block if present: { name, email, bio, avatar_url, socials[], background_image{url,imageBehavior} }
function extractProfileInfo(json) {
  if (!json) return undefined;
  // Prefer an explicit "profile" object anywhere in the tree
  let profileObj = undefined;
  const stack = [json];
  while (stack.length && !profileObj) {
    const cur = stack.pop();
    if (!cur) continue;
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push(v);
    } else if (typeof cur === 'object') {
      if (cur && typeof cur.profile === 'object' && !Array.isArray(cur.profile)) {
        profileObj = cur.profile;
        break;
      }
      for (const v of Object.values(cur)) stack.push(v);
    }
  }
  // Fallback: find an object that looks like a profile by keys
  if (!profileObj) {
    const keysHint = new Set(['name', 'email', 'bio', 'avatar_url', 'socials', 'background_image']);
    const seen = new Set();
    const st2 = [json];
    while (st2.length && !profileObj) {
      const cur = st2.pop();
      if (!cur || seen.has(cur)) continue;
      seen.add(cur);
      if (Array.isArray(cur)) { for (const v of cur) st2.push(v); }
      else if (typeof cur === 'object') {
        const keys = Object.keys(cur);
        const score = keys.reduce((acc, k) => acc + (keysHint.has(String(k)) ? 1 : 0), 0);
        if (score >= 2) { profileObj = cur; break; }
        for (const v of Object.values(cur)) st2.push(v);
      }
    }
  }
  if (!profileObj || typeof profileObj !== 'object') return undefined;
  const name = profileObj.name != null ? String(profileObj.name) : undefined;
  const email = profileObj.email != null ? String(profileObj.email) : undefined;
  const bio = profileObj.bio != null ? String(profileObj.bio) : undefined;
  const avatar_url = profileObj.avatar_url != null ? String(profileObj.avatar_url) : undefined;
  const socials = Array.isArray(profileObj.socials) ? profileObj.socials : undefined;
  let background_image = undefined;
  const bg = profileObj.background_image;
  if (bg && typeof bg === 'object') {
    background_image = {
      url: bg.url != null ? String(bg.url) : undefined,
      imageBehavior: bg.imageBehavior != null ? String(bg.imageBehavior) : undefined,
    };
  }
  return {
    profile: {
      ...(name !== undefined ? { name } : {}),
      ...(email !== undefined ? { email } : {}),
      ...(bio !== undefined ? { bio } : {}),
      ...(avatar_url !== undefined ? { avatar_url } : {}),
      ...(socials !== undefined ? { socials } : {}),
      ...(background_image !== undefined ? { background_image } : {}),
    }
  };
}

// Extract referral and related summary fields if present
function extractReferralAndXp(json) {
  if (!json) return {};
  let referred_by_address, referral_count, referral_eth_earnings;
  const seekKeys = new Set(['referred_by_address', 'referral_count', 'referral_eth_earnings']);
  const visited = new Set();
  const stack = [json];
  while (stack.length) {
    const cur = stack.pop();
    if (!cur || visited.has(cur)) continue;
    visited.add(cur);
    if (Array.isArray(cur)) { for (const v of cur) stack.push(v); }
    else if (typeof cur === 'object') {
      for (const [k,v] of Object.entries(cur)) {
        const lk = String(k);
        if (lk === 'referred_by_address' && referred_by_address === undefined && v != null) referred_by_address = String(v);
        if (lk === 'referral_count' && referral_count === undefined) {
          const n = Number(v); if (Number.isFinite(n)) referral_count = n;
        }
        if (lk === 'referral_eth_earnings' && referral_eth_earnings === undefined) {
          const n = Number(v); if (Number.isFinite(n)) referral_eth_earnings = n;
        }
      }
      for (const v of Object.values(cur)) stack.push(v);
    }
  }
  const xp = findMaxXpPoints(json);
  const out = {};
  if (referred_by_address !== undefined) out.referred_by_address = referred_by_address;
  if (referral_count !== undefined) out.referral_count = referral_count;
  if (referral_eth_earnings !== undefined) out.referral_eth_earnings = referral_eth_earnings;
  if (xp !== undefined) out.xp_points = xp;
  return out;
}

// Extract the first address from an "addresses" array anywhere in the payload
// and expose it as { user_evm: string }. If not found, returns {}.
function extractPrimaryEvmAddress(json) {
  if (!json) return {};
  const visited = new Set();
  const stack = [json];
  let addr = undefined;
  while (stack.length && addr === undefined) {
    const cur = stack.pop();
    if (!cur || visited.has(cur)) continue;
    visited.add(cur);
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push(v);
    } else if (typeof cur === 'object') {
      for (const [k, v] of Object.entries(cur)) {
        if (String(k).toLowerCase() === 'addresses' && Array.isArray(v) && v.length) {
          const first = v[0];
          if (first && typeof first === 'object' && 'address' in first) {
            const a = first.address;
            if (a != null) { addr = String(a); break; }
          }
        }
      }
      // Continue traversal in case we didn't find it at this level
      for (const v of Object.values(cur)) stack.push(v);
    }
  }
  return addr !== undefined ? { user_evm: addr } : {};
}

// GET /xps-ranked/profile-xp
// Reads IDs from a merged JSON file (default output/concat.json), calls user.getUserProfile per ID,
// extracts xp_points from the response JSON, writes results to output/profile-xp.json, and returns a summary.
// Query: jsonFile, idKey, limit, offset, concurrency, delayMs, outFile
app.get('/xps-ranked/profile-xp', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'concat.json');
    const idKey = req.query.idKey ? String(req.query.idKey) : 'user_id';
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    const offset = Number(req.query.offset ?? 0) || 0;
    const concurrency = Math.max(1, Number(req.query.concurrency ?? 2) || 2);
    const delayMs = Math.max(0, Number(req.query.delayMs ?? 250) || 250);
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const maxRetries = Math.max(0, Number(req.query.maxRetries ?? 4) || 4);
    const baseDelayMs = Math.max(50, Number(req.query.baseDelayMs ?? 500) || 500);
    const skipExisting = String(req.query.skipExisting ?? 'true').toLowerCase() !== 'false';
    const outMode = (req.query.outMode ? String(req.query.outMode) : 'merge').toLowerCase(); // overwrite | merge
    const backfill = String(req.query.backfill ?? 'true').toLowerCase() !== 'false';
    const mutateSource = String(req.query.mutateSource ?? 'false').toLowerCase() === 'true';

    const text = await fs.readFile(jsonFile, 'utf8');
    const arr = JSON.parse(text);
    if (!Array.isArray(arr)) return res.status(400).json({ error: 'Invalid JSON: expected top-level array' });

    // Build unique ordered ID list
    const seen = new Set();
    const ids = [];
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const idInfo = getIdFromObject(item, idKey);
      if (!idInfo) continue;
      const v = idInfo.value;
      const num = Number(v);
      if (!Number.isFinite(num) || num <= 0) continue; // userId must be positive number
      if (!seen.has(num)) {
        seen.add(num);
        ids.push(num);
      }
    }

    // Load existing output if we need to skip already processed
    let existing = undefined;
    const processedIds = new Set();
    if (skipExisting || outMode === 'merge') {
      try {
        const prev = JSON.parse(await fs.readFile(outFile, 'utf8'));
        existing = prev;
        if (Array.isArray(prev?.results)) {
          for (const r of prev.results) {
            if (r && (r.userId !== undefined && r.userId !== null)) {
              processedIds.add(Number(r.userId));
            }
          }
        }
      } catch {}
    }

    let slice;
    if (limit === undefined) {
      // Take all beyond offset (optionally skip existing)
      const all = ids.slice(offset);
      slice = skipExisting ? all.filter((id) => !processedIds.has(id)) : all;
    } else if (backfill) {
      // Fill up to 'limit' unprocessed ids by scanning beyond offset
      slice = [];
      for (let i = offset; i < ids.length && slice.length < limit; i++) {
        const id = ids[i];
        if (skipExisting && processedIds.has(id)) continue;
        slice.push(id);
      }
    } else {
      const sliceRaw = ids.slice(offset, offset + limit);
      slice = skipExisting ? sliceRaw.filter((id) => !processedIds.has(id)) : sliceRaw;
    }

    const headersOut = buildUpstreamHeaders(req.headers);
    if (auth) headersOut['authorization'] = auth;
    if (cookie) headersOut['cookie'] = cookie;

    const results = [];
    const errors = [];
    let completed = 0;
    let totalRetries = 0;

    // Backoff-aware fetch
    async function fetchWithRetries(url, headersOutLocal) {
      let attempt = 0;
      while (true) {
        try {
          const resp = await fetch(url, { method: 'GET', headers: headersOutLocal });
          if (resp.status === 429 || resp.status === 503) {
            if (attempt >= maxRetries) return { resp };
            // Respect Retry-After if present
            const ra = resp.headers.get('retry-after');
            let waitMs = baseDelayMs * Math.pow(2, attempt);
            if (ra) {
              const raNum = Number(ra);
              if (Number.isFinite(raNum)) waitMs = Math.max(waitMs, raNum * 1000);
            }
            // jitter
            waitMs = Math.round(waitMs * (1 + Math.random() * 0.25));
            attempt++;
            totalRetries++;
            await wait(waitMs);
            continue;
          }
          return { resp };
        } catch (e) {
          if (attempt >= maxRetries) return { error: e };
          const waitMs = Math.round(baseDelayMs * Math.pow(2, attempt) * (1 + Math.random() * 0.25));
          attempt++;
          totalRetries++;
          await wait(waitMs);
        }
      }
    }

    async function fetchOne(userId) {
      try {
        const inputParam = JSON.stringify({ userId });
        const url = 'https://common.xyz/api/internal/trpc/user.getUserProfile?input=' + encodeURIComponent(inputParam);
        const { resp, error } = await fetchWithRetries(url, headersOut);
        if (error) {
          errors.push({ userId, error: error?.message || String(error) });
          return;
        }
        const bodyText = await resp.text();
        let xp = undefined;
        try {
          const json = JSON.parse(bodyText);
          xp = findMaxXpPoints(json);
        } catch {}
        results.push({ userId, status: resp.status, ok: resp.ok, xp_points: xp ?? null });
        if (!resp.ok) {
          errors.push({ userId, status: resp.status, bodySample: bodyText.slice(0, 500) });
        }
      } catch (e) {
        errors.push({ userId, error: e?.message || String(e) });
      } finally {
        completed++;
        if (delayMs > 0) await wait(delayMs);
      }
    }

    // Simple promise pool
    const queue = slice.slice();
    const workers = Array.from({ length: Math.min(concurrency, queue.length || 0) }, async () => {
      while (queue.length) {
        const id = queue.shift();
        if (id === undefined) break;
        await fetchOne(id);
      }
    });
    await Promise.all(workers);

    // Persist results (merge or overwrite)
    await fs.mkdir(path.dirname(outFile), { recursive: true });
    if (outMode === 'merge' && existing && Array.isArray(existing.results)) {
      const byId = new Map();
      for (const r of existing.results) {
        if (r && (r.userId !== undefined && r.userId !== null)) byId.set(Number(r.userId), r);
      }
      for (const r of results) {
        if (r && (r.userId !== undefined && r.userId !== null)) byId.set(Number(r.userId), r);
      }
      const merged = {
        total: (existing.total || 0) + slice.length,
        completed: (existing.completed || 0) + completed,
        results: Array.from(byId.values()),
        errors: Array.isArray(existing.errors) ? existing.errors.concat(errors) : errors,
      };
      await fs.writeFile(outFile, JSON.stringify(merged, null, 2), 'utf8');
    } else {
      await fs.writeFile(outFile, JSON.stringify({ total: slice.length, completed, results, errors }, null, 2), 'utf8');
    }

    // Optionally mutate source JSON by removing processed IDs
    let removedFromSource = 0;
    if (mutateSource && slice.length > 0) {
      try {
        const srcText = await fs.readFile(jsonFile, 'utf8');
        const srcArr = JSON.parse(srcText);
        if (Array.isArray(srcArr)) {
          const toRemove = new Set(slice);
          const filtered = [];
          for (const item of srcArr) {
            if (!item || typeof item !== 'object') { filtered.push(item); continue; }
            const idInfo = getIdFromObject(item, idKey);
            if (!idInfo) { filtered.push(item); continue; }
            const num = Number(idInfo.value);
            if (!Number.isFinite(num)) { filtered.push(item); continue; }
            if (toRemove.has(num)) {
              removedFromSource++;
              continue;
            }
            filtered.push(item);
          }
          await fs.writeFile(jsonFile, JSON.stringify(filtered, null, 2), 'utf8');
        }
      } catch {}
    }

    return res.json({ ok: true, requested: slice.length, completed, successes: results.length - errors.length, failures: errors.length, skipped: Math.max(0, (limit ?? (ids.length - offset)) - slice.length), retries: totalRetries, outFile, outMode, skipExisting, backfill, mutateSource, removedFromSource });
  } catch (err) {
    return res.status(500).json({ error: 'Profile XP fetch failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-activity-runall
// concat.json içindeki tüm userId'ler için user.getUserProfile çağırır,
// addresses, threads, comments, totalUpvotes, commentThreads sayılarını çıkarır.
// Rate limit'e uyumlu, periyodik yazan ve resume edilebilir tasarım.
// Query: jsonFile (default output/concat.json), idKey (default user_id), outFile (default output/profile-activity.json),
//        concurrency (2), targetRps (1), flushEvery (100), baseDelayMs (500), maxRetries (6)
app.get('/xps-ranked/profile-activity-runall', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'concat.json');
    const idKey = req.query.idKey ? String(req.query.idKey) : 'user_id';
  const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
  const skipExisting = String(req.query.skipExisting ?? 'true').toLowerCase() !== 'false';
    const concurrency = Math.max(1, Number(req.query.concurrency ?? 2) || 2);
    const targetRps = Math.max(0.2, Number(req.query.targetRps ?? 1) || 1);
    const flushEvery = Math.max(10, Number(req.query.flushEvery ?? 100) || 100);
    const baseDelayMs = Math.max(100, Number(req.query.baseDelayMs ?? 500) || 500);
    const maxRetries = Math.max(0, Number(req.query.maxRetries ?? 6) || 6);

    const text = await fs.readFile(jsonFile, 'utf8');
    const arr = JSON.parse(text);
    if (!Array.isArray(arr)) return res.status(400).json({ error: 'Invalid JSON: expected top-level array' });

    // Unique userIds
    const seen = new Set();
    const allIds = [];
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const idInfo = getIdFromObject(item, idKey);
      if (!idInfo) continue;
      const num = Number(idInfo.value);
      if (!Number.isFinite(num) || num <= 0) continue;
      if (!seen.has(num)) { seen.add(num); allIds.push(num); }
    }

    // Resume from existing (skip IDs already present in outFile results)
    let existing = undefined;
    const doneIds = new Set();
    try {
      const prev = JSON.parse(await fs.readFile(outFile, 'utf8'));
      existing = prev;
      const resultsPrev = Array.isArray(prev?.results) ? prev.results : [];
      for (const r of resultsPrev) {
        if (!r) continue;
        // Be robust to different key casings
        const maybeId = r.userId ?? r.user_id ?? r.id;
        const num = Number(maybeId);
        if (Number.isFinite(num)) doneIds.add(num);
      }
    } catch {}

    const queue = skipExisting ? allIds.filter((id) => !doneIds.has(id)) : allIds.slice();

    const headersOut = buildUpstreamHeaders(req.headers);
    if (auth) headersOut['authorization'] = auth;
    if (cookie) headersOut['cookie'] = cookie;

    // Throttle logic
    let lastRequestTs = 0;
    const minInterval = 1000 / Math.max(0.1, targetRps);
    async function throttle() {
      const now = Date.now();
      const elapsed = now - lastRequestTs;
      if (elapsed < minInterval) await wait(minInterval - elapsed);
      lastRequestTs = Date.now();
    }

    async function fetchWithRetries(url) {
      let attempt = 0;
      while (true) {
        await throttle();
        try {
          const resp = await fetch(url, { method: 'GET', headers: headersOut });
          if (resp.status === 429 || resp.status === 503) {
            if (attempt >= maxRetries) return { resp };
            const ra = resp.headers.get('retry-after');
            let waitMs = baseDelayMs * Math.pow(2, attempt);
            if (ra) {
              const raNum = Number(ra);
              if (Number.isFinite(raNum)) waitMs = Math.max(waitMs, raNum * 1000);
            }
            await wait(waitMs);
            attempt++;
            continue;
          }
          return { resp };
        } catch (e) {
          if (attempt >= maxRetries) return { error: e };
          await wait(baseDelayMs * Math.pow(2, attempt));
          attempt++;
        }
      }
    }

    const results = existing && Array.isArray(existing.results) ? existing.results.slice() : [];
    const errors = existing && Array.isArray(existing.errors) ? existing.errors.slice() : [];
    let completed = existing?.completed || 0;
    let processedSinceFlush = 0;

    async function processOne(userId) {
      const inputParam = JSON.stringify({ userId });
      const url = 'https://common.xyz/api/internal/trpc/user.getUserProfile?input=' + encodeURIComponent(inputParam);
      const { resp, error } = await fetchWithRetries(url);
      if (error) {
        errors.push({ userId, error: error?.message || String(error) });
        completed++;
        processedSinceFlush++;
        return;
      }
      const bodyText = await resp.text();
      let activity = undefined;
      let profileMeta = undefined;
      let refer = undefined;
      let evm = undefined;
      try {
        const json = JSON.parse(bodyText);
        activity = computeProfileActivityCounts(json);
        profileMeta = extractProfileInfo(json);
        refer = extractReferralAndXp(json);
        evm = extractPrimaryEvmAddress(json);
      } catch {}
      results.push({ userId, status: resp.status, ok: resp.ok, ...activity, ...(profileMeta || {}), ...(refer || {}), ...(evm || {}) });
      if (!resp.ok) {
        errors.push({ userId, status: resp.status, bodySample: bodyText.slice(0, 500) });
      }
      completed++;
      processedSinceFlush++;
    }

    async function flushIfNeeded(force = false) {
      if (!force && processedSinceFlush < flushEvery) return;
      await fs.mkdir(path.dirname(outFile), { recursive: true });
      const payload = { total: results.length + errors.length, completed, results, errors };
      await fs.writeFile(outFile, JSON.stringify(payload, null, 2), 'utf8');
      processedSinceFlush = 0;
    }

    const workers = Array.from({ length: Math.min(concurrency, queue.length || 0) }, async () => {
      while (true) {
        const id = queue.shift();
        if (id === undefined) break;
        await processOne(id);
        await flushIfNeeded(false);
      }
    });
    await Promise.all(workers);
    await flushIfNeeded(true);

  return res.json({ ok: true, processed: completed, remaining: queue.length, results: results.length, errors: errors.length, outFile, skippedExisting: skipExisting ? doneIds.size : 0 });
  } catch (err) {
    return res.status(500).json({ error: 'Profile activity runall failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-xp-retry-errors
// Retries failed userIds found in output/profile-xp.json errors[] and updates results/errors in-place.
// Query: outFile (default output/profile-xp.json), limit (default 100), concurrency (2), targetRps (1),
//        baseDelayMs (500), maxRetries (6), filterStatus (comma-separated), flushEvery (50)
app.get('/xps-ranked/profile-xp-retry-errors', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const limit = Math.max(1, Number(req.query.limit ?? 100) || 100);
    const concurrency = Math.max(1, Number(req.query.concurrency ?? 2) || 2);
    const targetRps = Math.max(0.2, Number(req.query.targetRps ?? 1) || 1);
    const baseDelayMs = Math.max(100, Number(req.query.baseDelayMs ?? 500) || 500);
    const maxRetries = Math.max(0, Number(req.query.maxRetries ?? 6) || 6);
    const flushEvery = Math.max(10, Number(req.query.flushEvery ?? 50) || 50);
    const filterStatusRaw = req.query.filterStatus ? String(req.query.filterStatus) : undefined; // e.g., "429,503"
    const filterStatuses = filterStatusRaw ? new Set(filterStatusRaw.split(',').map((s) => Number(s.trim())).filter((n) => Number.isFinite(n))) : undefined;

    // Load existing output
    let data;
    try {
      data = JSON.parse(await fs.readFile(outFile, 'utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'Cannot read output file', message: e?.message || String(e), outFile });
    }
    const results = Array.isArray(data?.results) ? data.results : [];
    const errors = Array.isArray(data?.errors) ? data.errors : [];

    // Build retry ID list from errors
    const idsSet = new Set();
    for (const e of errors) {
      if (!e) continue;
      const id = e.userId ?? e.userid ?? e.id;
      const num = Number(id);
      if (!Number.isFinite(num)) continue;
      if (filterStatuses && e.status !== undefined && e.status !== null) {
        const st = Number(e.status);
        if (!filterStatuses.has(st)) continue;
      }
      idsSet.add(num);
      if (idsSet.size >= limit) break;
    }
    const queue = Array.from(idsSet);
    if (queue.length === 0) {
      return res.json({ ok: true, message: 'No error IDs to retry (or filtered out).', outFile });
    }

    const headersOut = buildUpstreamHeaders(req.headers);
    if (auth) headersOut['authorization'] = auth;
    if (cookie) headersOut['cookie'] = cookie;

    // Timing control
    let lastRequestTs = 0;
    const minInterval = 1000 / Math.max(0.1, targetRps);
    async function throttle() {
      const now = Date.now();
      const elapsed = now - lastRequestTs;
      if (elapsed < minInterval) await wait(minInterval - elapsed);
      lastRequestTs = Date.now();
    }

    async function fetchWithRetries(userId) {
      let attempt = 0;
      while (true) {
        await throttle();
        try {
          const inputParam = JSON.stringify({ userId });
          const url = 'https://common.xyz/api/internal/trpc/user.getUserProfile?input=' + encodeURIComponent(inputParam);
          const resp = await fetch(url, { method: 'GET', headers: headersOut });
          if (resp.status === 429 || resp.status === 503) {
            if (attempt >= maxRetries) return { resp };
            const ra = resp.headers.get('retry-after');
            let waitMs = baseDelayMs * Math.pow(2, attempt);
            if (ra) {
              const raNum = Number(ra);
              if (Number.isFinite(raNum)) waitMs = Math.max(waitMs, raNum * 1000);
            }
            await wait(waitMs);
            attempt++;
            continue;
          }
          return { resp };
        } catch (e) {
          if (attempt >= maxRetries) return { error: e };
          await wait(baseDelayMs * Math.pow(2, attempt));
          attempt++;
        }
      }
    }

    // Index for quick update
    const resultById = new Map();
    for (const r of results) {
      if (r && (r.userId !== undefined && r.userId !== null)) resultById.set(Number(r.userId), r);
    }

    function removeErrorsFor(id) {
      for (let i = errors.length - 1; i >= 0; i--) {
        const e = errors[i];
        const num = Number(e?.userId ?? e?.userid ?? e?.id);
        if (Number.isFinite(num) && num === id) errors.splice(i, 1);
      }
    }

    let processed = 0;
    let fixed = 0;
    let stillFail = 0;

    async function processOne(id) {
      const { resp, error } = await fetchWithRetries(id);
      if (error) {
        removeErrorsFor(id);
        errors.push({ userId: id, error: error?.message || String(error) });
        stillFail++;
      } else {
        const bodyText = await resp.text();
        let xp = undefined;
        try {
          const json = JSON.parse(bodyText);
          xp = findMaxXpPoints(json);
        } catch {}
        const entry = { userId: id, status: resp.status, ok: resp.ok, xp_points: xp ?? null };
        resultById.set(id, entry);
        removeErrorsFor(id);
        if (!resp.ok) {
          errors.push({ userId: id, status: resp.status, bodySample: bodyText.slice(0, 500) });
          stillFail++;
        } else {
          fixed++;
        }
      }
      processed++;
    }

    async function flush() {
      const newResults = Array.from(resultById.values());
      const payload = {
        total: data.total ?? newResults.length,
        completed: data.completed ?? newResults.length,
        results: newResults,
        errors,
      };
      await fs.writeFile(outFile, JSON.stringify(payload, null, 2), 'utf8');
    }

    const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      let sinceFlush = 0;
      while (true) {
        const id = queue.shift();
        if (id === undefined) break;
        await processOne(id);
        sinceFlush++;
        if (sinceFlush >= flushEvery) {
          await flush();
          sinceFlush = 0;
        }
      }
    });
    await Promise.all(workers);
    await flush();

    return res.json({ ok: true, attempted: processed, fixed, stillFail, outFile });
  } catch (err) {
    return res.status(500).json({ error: 'Profile XP retry-errors failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-activity-retry-errors
// output/profile-activity.json içindeki errors[] listesinden userId'leri alır (opsiyonel status filtreli),
// user.getUserProfile'ı tekrar çağırır, activity/metalar/referral ve user_evm'i yeniden hesaplar,
// results/errors dizilerini günceller ve dosyaya yazar.
// Query: outFile (default output/profile-activity.json), limit (100), concurrency (2), targetRps (1),
//        baseDelayMs (500), maxRetries (6), filterStatus (comma-separated), flushEvery (50)
app.get('/xps-ranked/profile-activity-retry-errors', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const limit = Math.max(1, Number(req.query.limit ?? 100) || 100);
    const concurrency = Math.max(1, Number(req.query.concurrency ?? 2) || 2);
    const targetRps = Math.max(0.2, Number(req.query.targetRps ?? 1) || 1);
    const baseDelayMs = Math.max(100, Number(req.query.baseDelayMs ?? 500) || 500);
    const maxRetries = Math.max(0, Number(req.query.maxRetries ?? 6) || 6);
    const flushEvery = Math.max(10, Number(req.query.flushEvery ?? 50) || 50);
    const filterStatusRaw = req.query.filterStatus ? String(req.query.filterStatus) : undefined; // e.g., "429,503,500"
    const filterStatuses = filterStatusRaw ? new Set(filterStatusRaw.split(',').map((s) => Number(s.trim())).filter((n) => Number.isFinite(n))) : undefined;

    // Mevcut çıktıyı yükle
    let data;
    try {
      data = JSON.parse(await fs.readFile(outFile, 'utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'Cannot read output file', message: e?.message || String(e), outFile });
    }
    const results = Array.isArray(data?.results) ? data.results : [];
    const errors = Array.isArray(data?.errors) ? data.errors : [];

    // Retry ID listesi (errors içinden)
    const idsSet = new Set();
    for (const e of errors) {
      if (!e) continue;
      const id = e.userId ?? e.userid ?? e.id;
      const num = Number(id);
      if (!Number.isFinite(num)) continue;
      if (filterStatuses && e.status !== undefined && e.status !== null) {
        const st = Number(e.status);
        if (!filterStatuses.has(st)) continue;
      }
      idsSet.add(num);
      if (idsSet.size >= limit) break;
    }
    const queue = Array.from(idsSet);
    if (queue.length === 0) {
      return res.json({ ok: true, message: 'No error IDs to retry (or filtered out).', outFile });
    }

    const headersOut = buildUpstreamHeaders(req.headers);
    if (auth) headersOut['authorization'] = auth;
    if (cookie) headersOut['cookie'] = cookie;

    // Zamanlama kontrolü
    let lastRequestTs = 0;
    const minInterval = 1000 / Math.max(0.1, targetRps);
    async function throttle() {
      const now = Date.now();
      const elapsed = now - lastRequestTs;
      if (elapsed < minInterval) await wait(minInterval - elapsed);
      lastRequestTs = Date.now();
    }

    async function fetchWithRetries(userId) {
      let attempt = 0;
      while (true) {
        await throttle();
        try {
          const inputParam = JSON.stringify({ userId });
          const url = 'https://common.xyz/api/internal/trpc/user.getUserProfile?input=' + encodeURIComponent(inputParam);
          const resp = await fetch(url, { method: 'GET', headers: headersOut });
          if (resp.status === 429 || resp.status === 503) {
            if (attempt >= maxRetries) return { resp };
            const ra = resp.headers.get('retry-after');
            let waitMs = baseDelayMs * Math.pow(2, attempt);
            if (ra) {
              const raNum = Number(ra);
              if (Number.isFinite(raNum)) waitMs = Math.max(waitMs, raNum * 1000);
            }
            await wait(waitMs);
            attempt++;
            continue;
          }
          return { resp };
        } catch (e) {
          if (attempt >= maxRetries) return { error: e };
          await wait(baseDelayMs * Math.pow(2, attempt));
          attempt++;
        }
      }
    }

    // Güncelleme için index
    const resultById = new Map();
    for (const r of results) {
      if (r && (r.userId !== undefined && r.userId !== null)) resultById.set(Number(r.userId), r);
    }

    function removeErrorsFor(id) {
      for (let i = errors.length - 1; i >= 0; i--) {
        const e = errors[i];
        const num = Number(e?.userId ?? e?.userid ?? e?.id);
        if (Number.isFinite(num) && num === id) errors.splice(i, 1);
      }
    }

    let processed = 0;
    let fixed = 0;
    let stillFail = 0;

    async function processOne(id) {
      const { resp, error } = await fetchWithRetries(id);
      if (error) {
        removeErrorsFor(id);
        errors.push({ userId: id, error: error?.message || String(error) });
        stillFail++;
      } else {
        const bodyText = await resp.text();
        let activity, profileMeta, refer, evm;
        try {
          const json = JSON.parse(bodyText);
          activity = computeProfileActivityCounts(json);
          profileMeta = extractProfileInfo(json);
          refer = extractReferralAndXp(json);
          evm = extractPrimaryEvmAddress(json);
        } catch {}
        const entry = { userId: id, status: resp.status, ok: resp.ok, ...(activity || {}), ...(profileMeta || {}), ...(refer || {}), ...(evm || {}) };
        resultById.set(id, entry);
        removeErrorsFor(id);
        if (!resp.ok) {
          errors.push({ userId: id, status: resp.status, bodySample: bodyText.slice(0, 500) });
          stillFail++;
        } else {
          fixed++;
        }
      }
      processed++;
    }

    async function flush() {
      const newResults = Array.from(resultById.values());
      const payload = {
        total: data.total ?? newResults.length,
        completed: data.completed ?? newResults.length,
        results: newResults,
        errors,
      };
      await fs.writeFile(outFile, JSON.stringify(payload, null, 2), 'utf8');
    }

    const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      let sinceFlush = 0;
      while (true) {
        const id = queue.shift();
        if (id === undefined) break;
        await processOne(id);
        sinceFlush++;
        if (sinceFlush >= flushEvery) {
          await flush();
          sinceFlush = 0;
        }
      }
    });
    await Promise.all(workers);
    await flush();

    return res.json({ ok: true, attempted: processed, fixed, stillFail, outFile });
  } catch (err) {
    return res.status(500).json({ error: 'Profile activity retry-errors failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/opensea-lamumu-runall
// profile-activity.json içinden user_evm ve userId alır; OpenSea v2 API ile cüzdandaki NFT'leri çeker,
// hedef contract (Lamumu) için toplam NFT sayısını hesaplar. Sonuçları JSON dosyasına yazar.
// Query: activityFile (default output/profile-activity.json), outFile (default output/opensea-lamumu.json),
//        contract (default 0x47d7b6116c2303f4d0232c767f71e00db166b67a), chain (default ethereum),
//        onlyOk=true|false, limit, offset, concurrency (2), targetRps (1), baseDelayMs (500), maxRetries (6),
//        flushEvery (50), maxPages (10). API key: header 'x-api-key' veya 'x-opensea-api-key' ya da query 'openseaApiKey'.
app.get('/xps-ranked/opensea-lamumu-runall', async (req, res) => {
  try {
    // API key'i al
    const hdrApiKey = req.headers['x-api-key'] || req.headers['x-opensea-api-key'];
    const qKey = typeof req.query.openseaApiKey === 'string' ? req.query.openseaApiKey : undefined;
  const apiKey = (hdrApiKey || qKey || process.env.OPENSEA_API_KEY);

    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'opensea-lamumu.json');
    const contract = (req.query.contract ? String(req.query.contract) : '0x47d7b6116c2303f4d0232c767f71e00db166b67a').toLowerCase();
    const chain = (req.query.chain ? String(req.query.chain) : 'ethereum').toLowerCase();
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    const offset = Number(req.query.offset ?? 0) || 0;
    const concurrency = Math.max(1, Number(req.query.concurrency ?? 2) || 2);
    const targetRps = Math.max(0.2, Number(req.query.targetRps ?? 1) || 1);
    const baseDelayMs = Math.max(100, Number(req.query.baseDelayMs ?? 500) || 500);
    const maxRetries = Math.max(0, Number(req.query.maxRetries ?? 6) || 6);
    const flushEvery = Math.max(10, Number(req.query.flushEvery ?? 50) || 50);
    const maxPages = Math.max(1, Number(req.query.maxPages ?? 10) || 10);

    // Girdi: profile-activity.json
    let activity;
    try {
      activity = JSON.parse(await fs.readFile(activityFile, 'utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'Cannot read activity file', message: e?.message || String(e), activityFile });
    }
    const arr = Array.isArray(activity?.results) ? activity.results : [];
    if (arr.length === 0) {
      return res.status(400).json({ error: 'No results in activity file', activityFile });
    }

    // Çıktıdan resume
    let existing = undefined;
    const doneKeys = new Set();
    try {
      existing = JSON.parse(await fs.readFile(outFile, 'utf8'));
      const prev = Array.isArray(existing?.results) ? existing.results : [];
      for (const r of prev) {
        const k = r && r.userId != null ? `${r.userId}|${String(r.user_evm || '').toLowerCase()}` : undefined;
        if (k) doneKeys.add(k);
      }
    } catch {}

    // İş kuyruğu: userId + user_evm olanlar
    const items = [];
    for (const r of arr) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const userId = r.userId ?? r.userid ?? r.id;
      const user_evm = r.user_evm;
      const uid = Number(userId);
      if (!Number.isFinite(uid) || uid <= 0) continue;
      if (!user_evm || typeof user_evm !== 'string') continue;
      const key = `${uid}|${user_evm.toLowerCase()}`;
      if (doneKeys.has(key)) continue;
      items.push({ userId: uid, user_evm });
    }

    // limit/offset uygula
    let slice = items.slice(offset);
    if (typeof limit === 'number') slice = slice.slice(0, limit);
    if (slice.length === 0) {
      return res.json({ ok: true, message: 'Nothing to process (empty slice after resume/filters).', outFile });
    }

    // RPS kontrolü
    let lastRequestTs = 0;
    const minInterval = 1000 / Math.max(0.1, targetRps);
    async function throttle() {
      const now = Date.now();
      const elapsed = now - lastRequestTs;
      if (elapsed < minInterval) await wait(minInterval - elapsed);
      lastRequestTs = Date.now();
    }

    function normalizeAddr(a) {
      if (!a) return undefined;
      let s = String(a).trim();
      if (!s.startsWith('0x') && /^[0-9a-fA-F]+$/.test(s)) s = '0x' + s;
      return s.toLowerCase();
    }

    function countForContractInPage(json, target) {
      let list = undefined;
      if (Array.isArray(json?.nfts)) list = json.nfts;
      else if (Array.isArray(json?.assets)) list = json.assets;
      else if (Array.isArray(json?.items)) list = json.items;
      if (!Array.isArray(list)) return 0;
      let c = 0;
      for (const it of list) {
        if (!it || typeof it !== 'object') continue;
        // possible shapes: { contract: '0x...' } or { contract: { address: '0x...' } } or { collection: { address: '0x...' } }
        let addr;
        if (typeof it.contract === 'string') addr = it.contract;
        else if (it.contract && typeof it.contract === 'object' && typeof it.contract.address === 'string') addr = it.contract.address;
        else if (it.collection && typeof it.collection === 'object' && typeof it.collection.address === 'string') addr = it.collection.address;
        if (addr && normalizeAddr(addr) === target) c++;
      }
      return c;
    }

    async function fetchOpenSeaPage(address, nextParam) {
      await throttle();
      const baseUrl = `https://api.opensea.io/api/v2/chain/${encodeURIComponent(chain)}/account/${encodeURIComponent(address)}/nfts`;
      const url = new URL(baseUrl);
      if (nextParam && typeof nextParam === 'string') {
        // Most v2 endpoints use 'next' as the cursor param
        url.searchParams.set('next', nextParam);
      }
      const headers = { 'accept': 'application/json', 'x-api-key': String(apiKey) };
      let attempt = 0;
      while (true) {
        try {
          const resp = await fetch(url.toString(), { method: 'GET', headers });
          if (resp.status === 429 || resp.status === 503) {
            if (attempt >= maxRetries) return { resp };
            const ra = resp.headers.get('retry-after');
            let waitMs = baseDelayMs * Math.pow(2, attempt);
            if (ra) {
              const n = Number(ra); if (Number.isFinite(n)) waitMs = Math.max(waitMs, n * 1000);
            }
            await wait(waitMs);
            attempt++;
            continue;
          }
          const text = await resp.text();
          let json = undefined;
          try { json = JSON.parse(text); } catch {}
          return { resp, json, body: text };
        } catch (e) {
          if (attempt >= maxRetries) return { error: e };
          await wait(baseDelayMs * Math.pow(2, attempt));
          attempt++;
        }
      }
    }

    async function processOne(userId, user_evm) {
      const addr = normalizeAddr(user_evm);
      if (!addr) return { entry: { userId, user_evm, ok: false }, error: { userId, user_evm, error: 'invalid evm address' } };
      let total = 0;
      let pages = 0;
      let cursor = undefined;
      let lastStatus = undefined;
      for (let i = 0; i < maxPages; i++) {
        const { resp, json, body, error } = await fetchOpenSeaPage(addr, cursor);
        if (error) {
          return { entry: { userId, user_evm: addr, ok: false }, error: { userId, user_evm: addr, error: error?.message || String(error) } };
        }
        lastStatus = resp?.status;
        if (!resp?.ok) {
          return { entry: { userId, user_evm: addr, ok: false, status: lastStatus }, error: { userId, user_evm: addr, status: lastStatus, bodySample: (body || '').slice(0, 500) } };
        }
        pages++;
        if (json) total += countForContractInPage(json, contract);
        // Cursor detection: common keys 'next', 'next_cursor', 'continuation'
        const nextCur = (typeof json?.next === 'string' && json.next)
          || (typeof json?.next_cursor === 'string' && json.next_cursor)
          || (typeof json?.continuation === 'string' && json.continuation)
          || undefined;
        if (!nextCur) break;
        cursor = nextCur;
      }
      return { entry: { userId, user_evm: addr, ok: true, lamumu_count: total, pages, status: lastStatus } };
    }

    const results = existing && Array.isArray(existing.results) ? existing.results.slice() : [];
    const errors = existing && Array.isArray(existing.errors) ? existing.errors.slice() : [];
    let completed = existing?.completed || 0;
    let sinceFlush = 0;

    async function flush(force = false) {
      if (!force && sinceFlush < flushEvery) return;
      await fs.mkdir(path.dirname(outFile), { recursive: true });
      const payload = { total: results.length + errors.length, completed, contract, chain, results, errors };
      await fs.writeFile(outFile, JSON.stringify(payload, null, 2), 'utf8');
      sinceFlush = 0;
    }

    const queue = slice.slice();
    const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (true) {
        const item = queue.shift();
        if (!item) break;
        const { entry, error } = await processOne(item.userId, item.user_evm);
        if (entry) results.push(entry);
        if (error) errors.push(error);
        completed++;
        sinceFlush++;
        await flush(false);
      }
    });
    await Promise.all(workers);
    await flush(true);

    return res.json({ ok: true, processed: completed, results: results.length, errors: errors.length, outFile, contract, chain });
  } catch (err) {
    return res.status(500).json({ error: 'OpenSea Lamumu runall failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-stats-lamumu-build
// Joins activity stats with Lamumu counts and writes a merged JSON file.
// Params:
//  - activityFile: input activity file (default output/profile-activity.json)
//  - lamumuFile: input lamumu results file (default output/opensea-lamumu.json)
//  - outFile: output merged file (default output/profile_stats_lamumu.json)
//  - onlyOk: filter activity by ok=true (default true)
//  - limit, offset: optional slicing over activity entries
app.get('/xps-ranked/profile-stats-lamumu-build', async (req, res) => {
  try {
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const lamumuFile = req.query.lamumuFile ? String(req.query.lamumuFile) : path.join(process.cwd(), 'output', 'opensea-lamumu.json');
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'profile_stats_lamumu.json');
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    const offset = Number(req.query.offset ?? 0) || 0;

    // Read activity file
    let activity;
    try {
      activity = JSON.parse(await fs.readFile(activityFile, 'utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'Cannot read activity file', message: e?.message || String(e), activityFile });
    }
    const actArr = Array.isArray(activity?.results) ? activity.results : [];
    if (actArr.length === 0) return res.status(400).json({ error: 'No results in activity file', activityFile });

    // Read lamumu file
    let lamumu;
    try {
      lamumu = JSON.parse(await fs.readFile(lamumuFile, 'utf8'));
    } catch (e) {
      lamumu = undefined; // allow missing; default counts to 0
    }
    const lamArr = Array.isArray(lamumu?.results) ? lamumu.results : [];
    // Build map of userId -> total lamumu_count (sum in case multiple addresses)
    const lamByUser = new Map();
    for (const r of lamArr) {
      if (!r || typeof r !== 'object') continue;
      const uid = Number(r.userId ?? r.userid ?? r.id);
      if (!Number.isFinite(uid)) continue;
      const c = Number(r.lamumu_count) || 0;
      lamByUser.set(uid, (lamByUser.get(uid) || 0) + c);
    }

    // Prepare slice of activity entries
    let items = actArr.filter((r) => {
      if (!r || typeof r !== 'object') return false;
      if (onlyOk && r.ok === false) return false;
      const uid = Number(r.userId ?? r.userid ?? r.id);
      return Number.isFinite(uid) && uid > 0;
    });
    items = items.slice(offset, typeof limit === 'number' ? offset + limit : undefined);

    const results = [];
    for (const r of items) {
      const user_id = Number(r.userId ?? r.userid ?? r.id) || 0;
      const display_name = r?.profile?.name ?? null;
      const avatar_url = r?.profile?.avatar_url ?? null;
      const xp_points = toNumber(r.xp_points) || 0;
      const addresses = toNumber(r.addresses) || 0;
      const threads = toNumber(r.threads) || 0;
      const comments = toNumber(r.comments) || 0;
      const total_upvotes = toNumber(r.totalUpvotes) || 0;
      const comment_threads = toNumber(r.commentThreads) || 0;
      const user_evm = typeof r.user_evm === 'string' ? r.user_evm : null;
      const lamumu_count = lamByUser.get(user_id) || 0;
      results.push({ user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, user_evm, lamumu_count });
    }

    // Persist output
    await fs.mkdir(path.dirname(outFile), { recursive: true });
    const payload = { total: results.length, completed: results.length, results };
    await fs.writeFile(outFile, JSON.stringify(payload, null, 2), 'utf8');

    return res.json({ ok: true, outFile, total: results.length });
  } catch (err) {
    return res.status(500).json({ error: 'profile-stats-lamumu-build failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-xp-stats
// Reads output/profile-xp.json and reports total xp_points and count of users over a threshold.
// Query: jsonFile (default output/profile-xp.json), threshold (default 1000), onlyOk (default true)
app.get('/xps-ranked/profile-xp-stats', async (req, res) => {
  try {
    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const threshold = Number(req.query.threshold ?? 1000) || 1000;
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';

    const text = await fs.readFile(jsonFile, 'utf8');
    const data = JSON.parse(text);
    const results = Array.isArray(data?.results) ? data.results : undefined;
    if (!results) {
      return res.status(400).json({ error: 'Invalid profile-xp JSON: results array not found' });
    }

    let totalXp = 0;
    let usersCounted = 0;
    let overThreshold = 0;
    for (const r of results) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const n = toNumber(r.xp_points);
      if (n === undefined) continue;
      usersCounted++;
      totalXp += n;
      if (n > threshold) overThreshold++;
    }

    const avgXp = usersCounted > 0 ? totalXp / usersCounted : 0;
    return res.json({ ok: true, jsonFile, usersCounted, totalXpPoints: totalXp, threshold, overThreshold, avgXpPoints: avgXp });
  } catch (err) {
    return res.status(500).json({ error: 'Profile XP stats failure', message: err?.message || String(err) });
  }
});

// POST/GET /xps-ranked/update-referred-by-from-merged
// Reads output/profile_stats_lamumu.json (merged file) and updates
// Supabase user_profile_stats.referred_by_address for each user_id using user_evm.
// Query/body params:
//   file: path to input JSON (default output/profile_stats_lamumu.json)
//   overwrite: true|false (default false) — overwrite non-empty values
//   dryRun: true|false (default false) — do not write, only return plan
//   batchSize: number (default 100)
//   offset: number (default 0), limit: number (optional)
//   onlyValidAddr: true|false (default true) — require 0x...40 format
app.all('/xps-ranked/update-referred-by-from-merged', async (req, res) => {
  if (!requireAdminInProd(req, res)) return;
  try {
    const file = String((req.body?.file ?? req.query.file) || path.join(process.cwd(), 'output', 'profile_stats_lamumu.json'));
    const overwrite = String(req.body?.overwrite ?? req.query.overwrite ?? 'false').toLowerCase() === 'true';
    const dryRun = String(req.body?.dryRun ?? req.query.dryRun ?? 'false').toLowerCase() === 'true';
    const onlyValidAddr = String(req.body?.onlyValidAddr ?? req.query.onlyValidAddr ?? 'true').toLowerCase() !== 'false';
  const batchSize = Math.max(1, Number(req.body?.batchSize ?? req.query.batchSize ?? 100) || 100);
  const sleepMs = Math.max(0, Number(req.body?.sleepMs ?? req.query.sleepMs ?? process.env.UPDATE_SLEEP_MS ?? 0) || 0);
  const concurrency = Math.max(1, Number(req.body?.concurrency ?? req.query.concurrency ?? process.env.UPDATE_CONCURRENCY ?? 5) || 5);
    const offset = Number(req.body?.offset ?? req.query.offset ?? 0) || 0;
    const limit = req.body?.limit != null || req.query.limit != null ? Number(req.body?.limit ?? req.query.limit) : undefined;

    // Read file
    let json;
    try {
      json = JSON.parse(await fs.readFile(file, 'utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'Cannot read input file', file, message: e?.message || String(e) });
    }
    const arr = Array.isArray(json?.results) ? json.results : Array.isArray(json) ? json : [];
    if (!Array.isArray(arr) || arr.length === 0) {
      return res.status(400).json({ error: 'No rows found in input', file });
    }

    // Slice
    const slice = arr.slice(offset, typeof limit === 'number' ? offset + limit : undefined);
    // Normalize entries
    const items = slice.map((r) => {
      const user_id = Number(r.user_id ?? r.userId ?? r.id);
      let user_evm = typeof r.user_evm === 'string' ? r.user_evm : (typeof r.userEvm === 'string' ? r.userEvm : null);
      if (typeof user_evm === 'string') user_evm = user_evm.trim().toLowerCase();
      return { user_id, user_evm };
    }).filter(r => Number.isFinite(r.user_id) && r.user_id > 0 && (r.user_evm || !onlyValidAddr));

    const isValidAddr = (a) => /^0x[a-f0-9]{40}$/.test(String(a || ''));
    const valid = items.filter(r => onlyValidAddr ? isValidAddr(r.user_evm) : true);

    const sb = getSupabase();

    // Simple concurrency pool runner
    const runPool = async (fns, c) => {
      let i = 0;
      const workers = Array(Math.min(c, fns.length)).fill(0).map(async () => {
        while (true) {
          const idx = i++;
          if (idx >= fns.length) break;
          await fns[idx]();
        }
      });
      await Promise.all(workers);
    };

    const results = [];
    let toUpdate = 0, updated = 0, skipped = 0, errors = 0;

    // Process in batches to reduce query sizes when selecting existing
    for (let i = 0; i < valid.length; i += batchSize) {
      const chunk = valid.slice(i, i + batchSize);
      const ids = chunk.map(x => x.user_id);

      // Fetch existing referred_by_address for this chunk when needed
      let existing = new Map();
      if (!overwrite) {
        try {
          const r = await sb.from('user_profile_stats').select('user_id,referred_by_address').in('user_id', ids);
          if (!r.error && Array.isArray(r.data)) {
            for (const row of r.data) {
              existing.set(Number(row.user_id), typeof row.referred_by_address === 'string' ? row.referred_by_address.toLowerCase() : (row.referred_by_address ?? null));
            }
          }
        } catch {}
      }

      const tasks = chunk.map((it) => async () => {
        const current = overwrite ? null : existing.get(it.user_id);
        const shouldUpdate = overwrite ? true : (!current || String(current).trim() === '');
        if (!shouldUpdate) { skipped++; results.push({ user_id: it.user_id, action: 'skip', current }); return; }
        toUpdate++;
        if (dryRun) { results.push({ user_id: it.user_id, action: 'would-update', value: it.user_evm }); return; }
        try {
          const up = await sb.from('user_profile_stats').update({ referred_by_address: it.user_evm }).eq('user_id', it.user_id);
          if (up.error) { errors++; results.push({ user_id: it.user_id, action: 'error', message: up.error.message }); }
          else { updated++; results.push({ user_id: it.user_id, action: 'updated', value: it.user_evm }); }
        } catch (e) {
          errors++; results.push({ user_id: it.user_id, action: 'error', message: e?.message || String(e) });
        }
        if (sleepMs > 0) await wait(sleepMs);
      });

      await runPool(tasks, concurrency);
    }

    const summary = {
      ok: true,
      file,
      totalInFile: arr.length,
      processed: valid.length,
      toUpdate,
      updated,
      skipped,
      errors,
      overwrite,
      dryRun,
      batchSize,
      offset,
      limit: typeof limit === 'number' ? limit : null,
      sample: results.slice(0, 20),
      sleepMs,
      concurrency,
    };
    return res.json(summary);
  } catch (err) {
    return res.status(500).json({ error: 'update-referred-by-from-merged failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-xp-sum
// Sums all xp_points from output/profile-xp.json (optionally only ok=true entries)
// Query: jsonFile (default output/profile-xp.json), onlyOk=true|false
app.get('/xps-ranked/profile-xp-sum', async (req, res) => {
  try {
    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';

    const text = await fs.readFile(jsonFile, 'utf8');
    const data = JSON.parse(text);
    const results = Array.isArray(data?.results) ? data.results : undefined;
    if (!results) return res.status(400).json({ error: 'Invalid file: results array missing', jsonFile });

    let totalXp = 0;
    let counted = 0;
    for (const r of results) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const n = toNumber(r.xp_points);
      if (n === undefined) continue;
      totalXp += n;
      counted++;
    }
    return res.json({ ok: true, jsonFile, onlyOk, counted, totalXpPoints: totalXp });
  } catch (err) {
    return res.status(500).json({ error: 'Profile XP sum failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/profile-xp-sum-20250926
// Sums all xp_points from output/profile-xp-20250926.json (optionally only ok=true entries)
// Query: onlyOk=true|false, jsonFile (optional override; default output/profile-xp-20250926.json)
app.get('/xps-ranked/profile-xp-sum-20250926', async (req, res) => {
  try {
    const defaultFile = path.join(process.cwd(), 'output', 'profile-xp-20250926.json');
    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : defaultFile;
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';

    const text = await fs.readFile(jsonFile, 'utf8');
    const data = JSON.parse(text);
    const results = Array.isArray(data?.results) ? data.results : undefined;
    if (!results) return res.status(400).json({ error: 'Invalid file: results array missing', jsonFile });

    let totalXp = 0;
    let counted = 0;
    for (const r of results) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const n = toNumber(r.xp_points);
      if (n === undefined) continue;
      totalXp += n;
      counted++;
    }
    return res.json({ ok: true, jsonFile, onlyOk, counted, totalXpPoints: totalXp });
  } catch (err) {
    return res.status(500).json({ error: 'Profile XP 20250926 sum failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/activity-xp-sum
// Sums all xp_points from output/profile-activity.json (optionally only ok=true entries)
// Also returns totals for addresses, threads, comments, totalUpvotes, commentThreads.
// Query: activityFile (default output/profile-activity.json), onlyOk=true|false, threshold (default 1000)
app.get('/xps-ranked/activity-xp-sum', async (req, res) => {
  try {
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
    const threshold = Number(req.query.threshold ?? 1000) || 1000;

    const text = await fs.readFile(activityFile, 'utf8');
    const data = JSON.parse(text);
    const results = Array.isArray(data?.results) ? data.results : undefined;
    if (!results) return res.status(400).json({ error: 'Invalid file: results array missing', activityFile });

    let totalXp = 0;
    let counted = 0;
    let zeroXpCount = 0;
    let overThreshold = 0;
    let totalAddresses = 0;
    let totalThreads = 0;
    let totalComments = 0;
    let totalUpvotes = 0;
    let totalCommentThreads = 0;
    for (const r of results) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const n = toNumber(r.xp_points);
      if (n === undefined) continue;
      totalXp += n;
      counted++;
      if (n === 0) zeroXpCount++;
      if (n > threshold) overThreshold++;
      totalAddresses += toNumber(r.addresses) || 0;
      totalThreads += toNumber(r.threads) || 0;
      totalComments += toNumber(r.comments) || 0;
      totalUpvotes += toNumber(r.totalUpvotes) || 0;
      totalCommentThreads += toNumber(r.commentThreads) || 0;
    }
    return res.json({ ok: true, activityFile, onlyOk, counted, totalXpPoints: totalXp, zeroXpCount, threshold, overThreshold, totalAddresses, totalThreads, totalComments, totalUpvotes, totalCommentThreads });
  } catch (err) {
    return res.status(500).json({ error: 'Activity XP sum failure', message: err?.message || String(err) });
  }
});

// Root → summary (no -html)
app.get('/', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/summary' + q);
});

// Root-level page routes will serve content directly (no /xps-ranked prefix)
// Canonical pages without -html
app.get('/common-checker', async (req, res) => {
  try { await renderCommonCheckerPage(req, res); } catch (err) { console.error('common-checker error:', err); return res.status(500).send('Internal Server Error'); }
});
app.get('/avg-allocation', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/common-checker' + q);
});
app.get('/summary', async (req, res) => {
  try {
    // Directly invoke the summary handler logic without changing the visible URL
    const xpFile = req.query.xpFile ? String(req.query.xpFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'summary.html');
    const writeFile = String(req.query.writeFile ?? 'true').toLowerCase() !== 'false';
    const canWrite = writeFile && !(process.env.VERCEL || process.env.NODE_ENV === 'production');
    const threshold = Number(req.query.threshold ?? 1000) || 1000;
    const useSupabase = String(req.query.useSupabase ?? 'true').toLowerCase() !== 'false';

    // Reuse the same logic as /xps-ranked/summary-html by calling its implementation
    // We simulate a call by requiring the function body inline here using a small wrapper
    // to avoid changing the URL or causing a redirect.
    // Implementation: call the existing handler function by invoking a local function.
    const handler = app._router.stack.find(layer => layer.route && layer.route.path === '/xps-ranked/summary-html')?.route?.stack?.[0]?.handle;
    if (typeof handler === 'function') {
      // Construct a shallow-cloned req with same query but without URL rewrite
      const proxyReq = Object.assign(Object.create(Object.getPrototypeOf(req)), req);
      await handler(proxyReq, res);
      return;
    }

    // Fallback: if we couldn't find the existing handler, read and return the static file
    try {
      const html = await fs.readFile(outFile, 'utf8');
      res.setHeader('content-type', 'text/html; charset=utf-8');
      return res.status(200).send(html);
    } catch {
      return res.status(500).send('Summary handler not available');
    }
  } catch (err) { console.error('summary error:', err); return res.status(500).send('Internal Server Error'); }
});
app.get('/users', async (req, res) => {
  try {
    req._internalForward = true;
    req.url = req.originalUrl.replace('/users', '/xps-ranked/users-html');
    await app._router.handle(req, res, () => {});
  } catch (err) { console.error('users error:', err); return res.status(500).send('Internal Server Error'); }
});

// Backwards compatibility: redirect old -html routes to new canonical
app.get('/common-checker-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/common-checker' + q);
});
app.get('/avg-allocation-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/common-checker' + q);
});
app.get('/summary-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/summary' + q);
});
app.get('/users-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/users' + q);
});
// Hide lamumu-holders page: redirect to users
app.get('/lamumu-holders-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/users' + q);
});
app.get('/xps-ranked/lamumu-holders-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/users' + q);
});

// Helpers for Common Checker
function normalizeEvm(addr) {
  if (!addr) return undefined;
  let s = String(addr).trim();
  if (!s) return undefined;
  if (!s.startsWith('0x')) {
    // If it's hex without 0x, add it
    if (/^[0-9a-fA-F]+$/.test(s)) s = '0x' + s;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return undefined;
  return s.toLowerCase();
}

async function findUserIdByEvmFromLocal(address, activityFile) {
  try {
    const txt = await fs.readFile(activityFile, 'utf8');
    const data = JSON.parse(txt);
    const arr = Array.isArray(data?.results) ? data.results : [];
    for (const r of arr) {
      const evm = r?.user_evm && String(r.user_evm).toLowerCase();
      if (evm === address) {
        const uid = Number(r.userId ?? r.userid ?? r.id);
        if (Number.isFinite(uid) && uid > 0) return uid;
      }
    }
  } catch {}
  return undefined;
}

async function countLamumuForAddress(address, opts = {}) {
  const chain = (opts.chain || 'ethereum').toLowerCase();
  const contract = (opts.contract || '0x47d7b6116c2303f4d0232c767f71e00db166b67a').toLowerCase();
  const apiKey = opts.apiKey;
  const maxPages = Math.max(1, Math.min(15, Number(opts.maxPages || 5)));
  const baseDelayMs = Math.max(100, Number(opts.baseDelayMs || 500));
  const maxRetries = Math.max(0, Number(opts.maxRetries || 4));

  function countForContractInPage(json, target) {
    let list = undefined;
    if (Array.isArray(json?.nfts)) list = json.nfts;
    else if (Array.isArray(json?.assets)) list = json.assets;
    else if (Array.isArray(json?.items)) list = json.items;
    if (!Array.isArray(list)) return 0;
    let c = 0;
    for (const it of list) {
      if (!it || typeof it !== 'object') continue;
      let addr;
      if (typeof it.contract === 'string') addr = it.contract;
      else if (it.contract && typeof it.contract === 'object' && typeof it.contract.address === 'string') addr = it.contract.address;
      else if (it.collection && typeof it.collection === 'object' && typeof it.collection.address === 'string') addr = it.collection.address;
      if (addr && String(addr).toLowerCase() === target) c++;
    }
    return c;
  }

  async function fetchOpenSeaPage(nextParam) {
    const baseUrl = `https://api.opensea.io/api/v2/chain/${encodeURIComponent(chain)}/account/${encodeURIComponent(address)}/nfts`;
    const url = new URL(baseUrl);
    if (nextParam) url.searchParams.set('next', nextParam);
    const headers = { 'accept': 'application/json' };
    if (apiKey) headers['x-api-key'] = String(apiKey);
    let attempt = 0;
    while (true) {
      try {
        const resp = await fetch(url.toString(), { method: 'GET', headers });
        if (resp.status === 429 || resp.status === 503) {
          if (attempt >= maxRetries) return { resp };
          const ra = resp.headers.get('retry-after');
          let waitMs = baseDelayMs * Math.pow(2, attempt);
          if (ra) {
            const n = Number(ra); if (Number.isFinite(n)) waitMs = Math.max(waitMs, n * 1000);
          }
          await wait(waitMs);
          attempt++;
          continue;
        }
        const body = await resp.text();
        let json = undefined;
        try { json = JSON.parse(body); } catch {}
        return { resp, json, body };
      } catch (e) {
        if (attempt >= maxRetries) return { error: e };
        await wait(baseDelayMs * Math.pow(2, attempt));
        attempt++;
      }
    }
  }

  let total = 0;
  let cursor = undefined;
  let pages = 0;
  let lastStatus = undefined;
  for (let i = 0; i < maxPages; i++) {
    const { resp, json, body, error } = await fetchOpenSeaPage(cursor);
    if (error) return { ok: false, error: error?.message || String(error) };
    lastStatus = resp?.status;
    if (!resp?.ok) return { ok: false, status: lastStatus, bodySample: (body || '').slice(0, 500) };
    pages++;
    if (json) total += countForContractInPage(json, contract);
    const nextCur = (typeof json?.next === 'string' && json.next)
      || (typeof json?.next_cursor === 'string' && json.next_cursor)
      || (typeof json?.continuation === 'string' && json.continuation)
      || undefined;
    if (!nextCur) break;
    cursor = nextCur;
  }
  return { ok: true, count: total, pages, status: lastStatus };
}

// Fetch Lamumu token holdings (token identifiers) for an address from OpenSea API
async function fetchLamumuHoldingsForAddress(address, opts = {}) {
  const chain = (opts.chain || 'ethereum').toLowerCase();
  const contract = (opts.contract || '0x47d7b6116c2303f4d0232c767f71e00db166b67a').toLowerCase();
  const apiKey = opts.apiKey;
  const maxPages = Math.max(1, Math.min(10, Number(opts.maxPages || 2)));
  const baseDelayMs = Math.max(100, Number(opts.baseDelayMs || 500));
  const maxRetries = Math.max(0, Number(opts.maxRetries || 4));

  function tokensForContractInPage(json, target) {
    let list = undefined;
    if (Array.isArray(json?.nfts)) list = json.nfts;
    else if (Array.isArray(json?.assets)) list = json.assets;
    else if (Array.isArray(json?.items)) list = json.items;
    if (!Array.isArray(list)) return [];
    const out = [];
    for (const it of list) {
      if (!it || typeof it !== 'object') continue;
      let addr;
      if (typeof it.contract === 'string') addr = it.contract;
      else if (it.contract && typeof it.contract === 'object' && typeof it.contract.address === 'string') addr = it.contract.address;
      else if (it.collection && typeof it.collection === 'object' && typeof it.collection.address === 'string') addr = it.collection.address;
      if (addr && String(addr).toLowerCase() !== target) continue;
      // identifier fields may differ; try common keys
      const idKeys = ['identifier', 'token_id', 'tokenId', 'nft_id', 'id'];
      let tokenId;
      for (const k of idKeys) { if (it[k] != null) { tokenId = String(it[k]); break; } }
      // Some responses nest identifier under it.identifier or it.nft.identifier
      if (!tokenId && it.nft && typeof it.nft === 'object') {
        for (const k of idKeys) { if (it.nft[k] != null) { tokenId = String(it.nft[k]); break; } }
      }
      if (!tokenId) continue;
      const name = (typeof it.name === 'string' && it.name) || (typeof it.nft?.name === 'string' && it.nft.name) || undefined;
      out.push({ token_id: tokenId, name });
    }
    return out;
  }

  async function fetchOpenSeaPage(nextParam) {
    const baseUrl = `https://api.opensea.io/api/v2/chain/${encodeURIComponent(chain)}/account/${encodeURIComponent(address)}/nfts`;
    const url = new URL(baseUrl);
    if (nextParam) url.searchParams.set('next', nextParam);
    const headers = { 'accept': 'application/json' };
    if (apiKey) headers['x-api-key'] = String(apiKey);
    let attempt = 0;
    while (true) {
      try {
        const resp = await fetch(url.toString(), { method: 'GET', headers });
        if (resp.status === 429 || resp.status === 503) {
          if (attempt >= maxRetries) return { resp };
          const ra = resp.headers.get('retry-after');
          let waitMs = baseDelayMs * Math.pow(2, attempt);
          if (ra) { const n = Number(ra); if (Number.isFinite(n)) waitMs = Math.max(waitMs, n * 1000); }
          await wait(waitMs);
          attempt++; continue;
        }
        const body = await resp.text();
        let json = undefined; try { json = JSON.parse(body); } catch {}
        return { resp, json, body };
      } catch (e) {
        if (attempt >= maxRetries) return { error: e };
        await wait(baseDelayMs * Math.pow(2, attempt)); attempt++;
      }
    }
  }

  const tokens = [];
  let cursor = undefined;
  let pages = 0;
  let lastStatus = undefined;
  for (let i = 0; i < maxPages; i++) {
    const { resp, json, body, error } = await fetchOpenSeaPage(cursor);
    if (error) return { ok: false, error: error?.message || String(error) };
    lastStatus = resp?.status;
    if (!resp?.ok) return { ok: false, status: lastStatus, bodySample: (body || '').slice(0, 500) };
    pages++;
    if (json) tokens.push(...tokensForContractInPage(json, contract));
    const nextCur = (typeof json?.next === 'string' && json.next)
      || (typeof json?.next_cursor === 'string' && json.next_cursor)
      || (typeof json?.continuation === 'string' && json.continuation)
      || undefined;
    if (!nextCur) break; cursor = nextCur;
  }
  return { ok: true, tokens, pages, status: lastStatus };
}

// Fetch rarity rank for a single Lamumu token via OpenSea v2 token endpoint
async function fetchLamumuTokenRarity({ chain = 'ethereum', contract = '0x47d7b6116c2303f4d0232c767f71e00db166b67a', tokenId, apiKey, baseDelayMs = 400, maxRetries = 3 }) {
  if (!tokenId) return { ok: false, error: 'missing tokenId' };
  const url = `https://api.opensea.io/api/v2/chain/${encodeURIComponent(chain)}/contract/${encodeURIComponent(contract)}/nfts/${encodeURIComponent(String(tokenId))}`;
  const headers = { 'accept': 'application/json' };
  if (apiKey) headers['x-api-key'] = String(apiKey);
  let attempt = 0;
  while (true) {
    try {
      const resp = await fetch(url, { method: 'GET', headers });
      if (resp.status === 429 || resp.status === 503) {
        if (attempt >= maxRetries) return { ok: false, status: resp.status };
        const ra = resp.headers.get('retry-after');
        let waitMs = baseDelayMs * Math.pow(2, attempt);
        if (ra) { const n = Number(ra); if (Number.isFinite(n)) waitMs = Math.max(waitMs, n * 1000); }
        await wait(waitMs); attempt++; continue;
      }
      const body = await resp.text();
      let json = undefined; try { json = JSON.parse(body); } catch {}
      if (!resp.ok) return { ok: false, status: resp.status, bodySample: (body||'').slice(0,400) };
      // Probe common fields for rarity rank
      const rar = (json && (json.rarity || json.nft?.rarity || json.data?.rarity)) || {};
      let rank = toNumber(rar.rank);
      if (!Number.isFinite(rank)) {
        // Some payloads may have rarity_rank or ranking.rank
        rank = toNumber(json?.rarity_rank) ?? toNumber(json?.nft?.rarity_rank) ?? toNumber(json?.ranking?.rank) ?? undefined;
      }
      return { ok: true, rank: Number.isFinite(rank) ? rank : undefined, json };
    } catch (e) {
      if (attempt >= maxRetries) return { ok: false, error: e?.message || String(e) };
      await wait(baseDelayMs * Math.pow(2, attempt)); attempt++;
    }
  }
}

// Common Checker page renderer (shared by both canonical paths)
async function renderCommonCheckerPage(req, res) {
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  const qType = (() => {
    if (!q) return '';
    const isAddr = /^0x[a-fA-F0-9]{40}$/.test(q);
    return isAddr ? 'EVM Address' : 'Unknown';
  })();
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Global: compute Per Aura with split pool (default 32,500,000 / summary_stats.total_aura)
  let perAuraVal = null;
  // Global: compute Per Activity Unit with split pool (default 32,500,000 / (total_threads+total_comments+total_upvotes))
  let perActivityUnitVal = null;
  let perAuraBlock = '';
  // Optional override for total Aura denominator (e.g., use Tier 4+ users total)
  const totalAuraOverride = (() => {
    const raw = (process.env.AURA_TOTAL_AURA_OVERRIDE ?? req.query.totalAura);
    if (raw == null) return null;
    const n = Number(String(raw).replace(/[,_\s]/g, ''));
    return (Number.isFinite(n) && n > 0) ? n : null;
  })();
  // Global: compute $COMMON price using total supply 10,000,000,000 and optional valuation
  const TOTAL_COMMON_SUPPLY = 10_000_000_000;
  const valuationRaw = req.query.valuationUsd ?? process.env.COMMON_VALUATION_USD;
  const valuationUsd = valuationRaw != null ? Number(String(valuationRaw).replace(/[,\s$]/g, '')) : null;
  const pricePerCommon = (valuationUsd != null && Number.isFinite(valuationUsd) && valuationUsd > 0)
    ? (valuationUsd / TOTAL_COMMON_SUPPLY)
    : null;
  const fmtPrice = (x) => (typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 8 }) : '—');
  let priceBlock = '';
  // Global: compute Per Lamumu (env-configurable; defaults 85,000,000 / 4,500)
  const LAMUMU_SUPPLY_GLOBAL = Number(process.env.LAMUMU_POOL_SUPPLY ?? 85_000_000);
  const LAMUMU_TOTAL_GLOBAL = Number(process.env.LAMUMU_TOTAL_COUNT ?? 4_500);
  const lamumuPerVal = LAMUMU_SUPPLY_GLOBAL / LAMUMU_TOTAL_GLOBAL;
  const fmtDecGlobal = (x) => (typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('en-US', { maximumFractionDigits: 6 }) : '—');
  let lamumuPerBlock = '';
  let perUnitBlock = '';
  // Read allocation percentages from env for the notice (defaults if missing)
  const lamumuAllocPct = parsePct(process.env.LAMUMU_ALLOCATION_PERCENT, 0.9);
  const auraAllocPct = parsePct(process.env.AURA_ALLOCATION_PERCENT, 0.6);
  // Track the total Aura denominator actually used for Per Aura (for UI hint)
  let totalAuraUsed = null;
  try {
    const sb = getSupabase();
    let totalAura = null;
    let sumRow = null;
    // Pull total_aura plus activity totals for activity-based allocation
    let ss = await sb.from('summary_stats').select('id,total_aura,total_threads,total_comments,total_upvotes,updated_at').eq('id', 1).maybeSingle();
    if (!ss.error && ss.data) {
      sumRow = ss.data;
    } else {
      const ss2 = await sb.from('summary_stats').select('id,total_aura,total_threads,total_comments,total_upvotes,updated_at').limit(1);
      if (!ss2.error && Array.isArray(ss2.data) && ss2.data[0]) sumRow = ss2.data[0];
    }
    if (sumRow && sumRow.total_aura != null) totalAura = Number(sumRow.total_aura);
    totalAuraUsed = totalAuraOverride ?? totalAura;
    // Per Aura (Aura pool share)
    if (Number.isFinite(totalAuraUsed) && totalAuraUsed > 0) {
      const AURA_AURA_POOL_SUPPLY = Number(process.env.AURA_AURA_POOL_SUPPLY ?? 32_500_000);
      perAuraVal = AURA_AURA_POOL_SUPPLY / totalAuraUsed;
    }
    // Per Activity Unit (Activity pool share)
  const actTotals = sumRow || {};
  const tThreads = Number(actTotals.total_threads);
  const tComments = Number(actTotals.total_comments);
  const tUpvotes = Number(actTotals.total_upvotes);
    const denom = [tThreads, tComments, tUpvotes]
      .map((n) => (Number.isFinite(n) && n > 0 ? n : 0))
      .reduce((a, b) => a + b, 0);
    if (denom > 0) {
      const AURA_ACTIVITY_POOL_SUPPLY = Number(process.env.AURA_ACTIVITY_POOL_SUPPLY ?? 32_500_000);
      perActivityUnitVal = AURA_ACTIVITY_POOL_SUPPLY / denom;
    }
  } catch {}

  // Combined Per-Unit block (Per Aura only) — Per Lamumu removed per request
  perUnitBlock = `
    <div class="row" style="display:flex; gap:14px; flex-wrap:wrap; margin-top:14px">
      <div class="card" style="flex:1; min-width:260px">
        <div class="title">Per Aura</div>
        <div class="title" style="margin-top:6px">${fmtDecGlobal(perAuraVal)}</div>
        ${(Number.isFinite(totalAuraUsed) && totalAuraUsed > 0) ? `<div class=\"hint\">Total Aura used in calc: ${Number(totalAuraUsed).toLocaleString('en-US')} ${totalAuraOverride != null ? '(Tier 4+ users)' : ''}</div>` : ''}
      </div>
    </div>`;

  // Results blocks
  let resultBlock = '';
  // EVM address flow
  if (q && qType === 'EVM Address') {
    const isProd = (process.env.VERCEL || process.env.NODE_ENV === 'production');
    const addr = normalizeEvm(q);
    const msgs = [];
  let lamumuCount = null;
  let lamumuTokens = null; // [{token_id, name?}]
    let userId = null;
    let aura = null;
    // For activity-based allocation
    let userActivityPoints = null; // threads + comments + total_upvotes

    // 1) OpenSea Lamumu count
    // Use server-side key only (env); if missing, skip OpenSea calls and stay silent in production
    const apiKey = (process.env.OPENSEA_API_KEY);
    try {
      if (apiKey) {
        const lam = await countLamumuForAddress(addr, {
          apiKey,
          chain: String(req.query.chain || 'ethereum'),
          contract: String(req.query.contract || '0x47d7b6116c2303f4d0232c767f71e00db166b67a'),
          maxPages: Number(req.query.maxPages || 5),
        });
        if (lam.ok) {
          lamumuCount = lam.count;
        } else {
          // Do not surface raw OpenSea errors in UI; log server-side for debugging
          if (!isProd) msgs.push('OpenSea verisi alınamadı.');
          console.warn('OpenSea count error', { status: lam.status, err: lam.bodySample || lam.error });
        }
        if (lam.ok && lam.count > 0) {
          const det = await fetchLamumuHoldingsForAddress(addr, {
            apiKey,
            chain: String(req.query.chain || 'ethereum'),
            contract: String(req.query.contract || '0x47d7b6116c2303f4d0232c767f71e00db166b67a'),
            maxPages: Number(req.query.lamPages || 2),
          });
          if (det.ok) {
            lamumuTokens = det.tokens;
            // If no local rarity file, enrich first few tokens with rank via OpenSea token endpoint
              const envFetchDefault = (process.env.LAMUMU_FETCH_RARITY_DEFAULT ?? null);
              const defaultFetch = (envFetchDefault != null)
                ? String(envFetchDefault).toLowerCase() !== 'false'
                : (apiKey ? true : (!isProd));
              const fetchRarity = String(req.query.fetchRarity ?? String(defaultFetch)).toLowerCase() !== 'false';
            if (fetchRarity && Array.isArray(lamumuTokens) && lamumuTokens.length) {
              const rarityFile = req.query.rarityFile ? String(req.query.rarityFile) : path.join(process.cwd(), 'output', 'lamumu-rarity.json');
              let hasLocal = false;
              // Treat HTTP/HTTPS URL as available source to avoid unnecessary API calls
              if (/^https?:\/\//i.test(rarityFile)) {
                hasLocal = true;
              } else {
                try { await fs.access(rarityFile); hasLocal = true; } catch {}
              }
              if (!hasLocal) {
              const limitEnv = process.env.LAMUMU_RARITY_FETCH_LIMIT;
              // Cap the per-address rarity fetch to a maximum of 200 tokens
              let limit = Math.max(1, Number(req.query.rarityLimit ?? (limitEnv ?? 10)) || 10);
              limit = Math.min(200, limit);
                const chain = String(req.query.chain || 'ethereum');
                const contract = String(req.query.contract || '0x47d7b6116c2303f4d0232c767f71e00db166b67a');
                for (const t of lamumuTokens.slice(0, limit)) {
                  if (!t || t.token_id == null) continue;
                  const r = await fetchLamumuTokenRarity({ chain, contract, tokenId: String(t.token_id), apiKey });
                  if (r.ok && Number.isFinite(r.rank)) t.rank = Number(r.rank);
                }
              }
            }
          } else {
            if (!isProd) msgs.push('OpenSea detayları alınamadı.');
            console.warn('OpenSea holdings error', { status: det.status, err: det.bodySample || det.error });
          }
        }
      } else {
        // No API key configured; skip OpenSea entirely (avoid 401s in production)
        if (!isProd) msgs.push('OpenSea API key yok; Lamumu verisi atlandı.');
      }
    } catch (e) {
      if (!isProd) msgs.push('OpenSea lookup hata: ' + esc(e?.message || String(e)));
      console.warn('OpenSea lookup exception', e);
    }

    // 2) Map EVM -> user_id via local file
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    try {
  const uid = await findUserIdByEvmFromLocal(addr, activityFile);
  if (uid) userId = uid; // if not found, stay silent
    } catch (e) {
      msgs.push('Local mapping lookup failed: ' + esc(e?.message || String(e)));
    }

    // 3) Supabase fallback by EVM: try referred_by_address -> resolve user_id and/or Aura
    if (!userId || aura == null) {
      try {
        const sb = getSupabase();
        const r = await sb.from('user_profile_stats').select('user_id,xp_points,referred_by_address').ilike('referred_by_address', addr).maybeSingle();
        if (!r.error && r.data) {
          if (!userId) {
            const uid = Number(r.data.user_id);
            if (Number.isFinite(uid) && uid > 0) userId = uid;
          }
          if (aura == null && r.data.xp_points != null) {
            const n = Number(r.data.xp_points);
            if (Number.isFinite(n)) aura = n;
          }
        }
      } catch (e) {
        msgs.push('Supabase address lookup failed: ' + esc(e?.message || String(e)));
      }
    }

    // 4) Fetch xp_points (Aura) from Supabase by user_id if still needed
    if (userId && aura == null) {
      try {
        const sb = getSupabase();
        let got = null;
        // Prefer user_profile_stats.xp_points
        const r1 = await sb.from('user_profile_stats').select('xp_points').eq('user_id', userId).maybeSingle();
        if (!r1.error && r1.data && r1.data.xp_points != null) {
          got = Number(r1.data.xp_points);
        } else {
          // Fallback to user_xp
          const r2 = await sb.from('user_xp').select('xp_points').eq('user_id', userId).maybeSingle();
          if (!r2.error && r2.data && r2.data.xp_points != null) got = Number(r2.data.xp_points);
        }
        if (got != null && Number.isFinite(got)) aura = got; else msgs.push('Aura (xp_points) not found in Supabase for this user.');
      } catch (e) {
        msgs.push('Supabase lookup failed: ' + esc(e?.message || String(e)));
      }
    }

    // 5) Fetch user activity (threads + comments + total_upvotes) for activity-based allocation
    if (userId && userActivityPoints == null) {
      try {
        const sb = getSupabase();
        // Prefer user_profile_stats
        const r = await sb.from('user_profile_stats').select('threads, comments, total_upvotes').eq('user_id', userId).maybeSingle();
        let thr, com, upv;
        if (!r.error && r.data) {
          thr = Number(r.data.threads);
          com = Number(r.data.comments);
          upv = Number(r.data.total_upvotes);
        } else {
          // Fallback to user_activity
          const r2 = await sb.from('user_activity').select('threads, comments, total_upvotes').eq('user_id', userId).maybeSingle();
          if (!r2.error && r2.data) {
            thr = Number(r2.data.threads);
            com = Number(r2.data.comments);
            upv = Number(r2.data.total_upvotes);
          }
        }
        const okThr = Number.isFinite(thr) && thr > 0 ? thr : 0;
        const okCom = Number.isFinite(com) && com > 0 ? com : 0;
        const okUpv = Number.isFinite(upv) && upv > 0 ? upv : 0;
        userActivityPoints = okThr + okCom + okUpv;
      } catch (e) {
        msgs.push('Supabase activity lookup failed: ' + esc(e?.message || String(e)));
      }
    }

    // 6) Combined per-user allocation (Aura, Lamumu, Common Activity, Total) shown after search
    let allocationBlock = '';
    try {
      const fmtDec = (x) => (typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('en-US', { maximumFractionDigits: 6 }) : '—');
      const fmtUsd = (x) => (typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 2 }) : '—');
      const fmtPrice6 = (x) => (typeof x === 'number' && Number.isFinite(x) ? x.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 6 }) : '—');
      const auraAlloc = (perAuraVal != null && aura != null && Number.isFinite(aura)) ? aura * perAuraVal : null;

      // Lamumu allocation: rarity-weighted if token-level ranks available, else uniform perLamumu
      let lamAlloc = null;
      let lamAllocHint = '';
      if (Array.isArray(lamumuTokens) && lamumuTokens.length > 0) {
        // Build rarity map once
        const rarityFile = req.query.rarityFile ? String(req.query.rarityFile) : path.join(process.cwd(), 'output', 'lamumu-rarity.json');
        let rarityMap = null; // token_id -> { rank, score }
        try {
          const rarityDataTxt = await fs.readFile(rarityFile, 'utf8');
          const rarityData = JSON.parse(rarityDataTxt);
          rarityMap = new Map();
          if (Array.isArray(rarityData)) {
            for (const r of rarityData) {
              if (!r || typeof r !== 'object') continue;
              const tid = r.token_id != null ? String(r.token_id) : (r.id != null ? String(r.id) : undefined);
              if (!tid) continue;
              const rank = toNumber(r.rank);
              const score = toNumber(r.score) ?? toNumber(r.rarity_score);
              rarityMap.set(tid, { rank, score });
            }
          } else if (rarityData && typeof rarityData === 'object') {
            for (const [k, v] of Object.entries(rarityData)) {
              if (!k) continue; const tid = String(k);
              const rank = toNumber(v?.rank);
              const score = toNumber(v?.score) ?? toNumber(v?.rarity_score);
              rarityMap.set(tid, { rank, score });
            }
          }
        } catch {}

        const perTokenByRank = (rank) => (Number.isFinite(rank) && rank <= 350) ? 21100 : (Number.isFinite(rank) && rank <= 750) ? 18500 : 16200;
        let sum = 0;
        for (const t of lamumuTokens) {
          const tid = t?.token_id != null ? String(t.token_id) : undefined;
          let rank = Number.isFinite(toNumber(t?.rank)) ? toNumber(t.rank) : (tid && rarityMap ? toNumber(rarityMap.get(tid)?.rank) : undefined);
          if (!Number.isFinite(rank)) {
            // Fallback: treat token_id as rank if numeric (e.g., #2867 means rank 2867)
            const n = tid != null ? Number(String(tid).replace(/[^0-9.-]/g, '')) : NaN;
            if (Number.isFinite(n)) rank = n;
          }
          sum += perTokenByRank(rank);
        }
        lamAlloc = sum;
        lamAllocHint = 'rarity-weighted';
      } else {
        lamAlloc = (typeof lamumuCount === 'number' && Number.isFinite(lamumuCount)) ? lamumuCount * lamumuPerVal : null;
        lamAllocHint = 'uniform';
      }

      const actAlloc = (perActivityUnitVal != null && userActivityPoints != null && Number.isFinite(userActivityPoints)) ? userActivityPoints * perActivityUnitVal : null;
      const totalAlloc = (auraAlloc ?? 0) + (lamAlloc ?? 0) + (actAlloc ?? 0);
      if (auraAlloc != null || lamAlloc != null || actAlloc != null) {
        const FDV_SCENARIOS = [250_000_000, 500_000_000, 1_000_000_000];
        const scenarioHtml = (() => {
          if (!Number.isFinite(totalAlloc) || totalAlloc <= 0) return '';
          const rows = FDV_SCENARIOS.map(fdv => {
            const price = fdv / 10_000_000_000;
            const valTotal = totalAlloc * price;
            const valP1 = (totalAlloc * 0.5) * price;
            const valP2 = (totalAlloc * 0.5) * price;
            const label = fdv >= 1_000_000_000 ? 'FDV 1B' : `FDV ${Math.round(fdv/1_000_000)}M`;
            return `
              <div class="card" style="flex:1">
                <div class="label">${label}</div>
                <div class="hint">Price: ${fmtPrice6(price)}</div>
                <div class="row" style="margin-top:8px; gap:10px">
                  <div style="flex:1">
                    <div class="label">Phase 1 (50%)</div>
                    <div class="title">${fmtUsd(valP1)}</div>
                  </div>
                  <div style="flex:1">
                    <div class="label">Phase 2 (50%)</div>
                    <div class="title">${fmtUsd(valP2)}</div>
                  </div>
                </div>
                <div class="hint" style="margin-top:6px">Total (100%): ${fmtUsd(valTotal)}</div>
              </div>`;
          }).join('');
          return `
            <div class="label" style="margin-top:8px">Scenario values (2 phases @ 50%/50%)</div>
            <div class="row" style="margin-top:8px">${rows}</div>`;
        })();
        allocationBlock = `
          <div class="card" style="margin-top:14px">
            <div class="title">Your Allocation</div>
            
            <div class="row" style="margin-top:10px">
              <div class="card" style="flex:1">
                <div class="label">Aura Allocation</div>
                <div class="title">${fmtDec(auraAlloc)}</div>
                ${pricePerCommon != null ? `<div class="hint">${fmtUsd(auraAlloc * pricePerCommon)}</div>` : ''}
              </div>
              <div class="card" style="flex:1">
                <div class="label">Lamumu Allocation</div>
                <div class="title">${fmtDec(lamAlloc)}</div>
                ${pricePerCommon != null ? `<div class="hint">${fmtUsd(lamAlloc * pricePerCommon)}</div>` : ''}
                <div class="hint">${lamAllocHint}</div>
              </div>
              <div class="card" style="flex:1">
                <div class="label">Common Activity Allocation</div>
                <div class="title">${fmtDec(actAlloc)}</div>
                ${pricePerCommon != null ? `<div class="hint">${fmtUsd(actAlloc * pricePerCommon)}</div>` : ''}
              </div>
              <div class="card" style="flex:1">
                <div class="label">Total Allocation</div>
                <div class="title">${fmtDec((auraAlloc==null && lamAlloc==null) ? null : totalAlloc)}</div>
                ${pricePerCommon != null ? `<div class="hint">${fmtUsd(totalAlloc * pricePerCommon)}</div>` : ''}
              </div>
            </div>
            ${scenarioHtml}
          </div>`;
      }
    } catch {}

    const fmt = (n) => (typeof n === 'number' && Number.isFinite(n) ? n.toLocaleString('en-US') : '—');
    // Optional rarity mapping: output/lamumu-rarity.json (object or array). Each entry should provide token_id and rank/score.
    let lamumuRarityBlock = '';
    try {
      if (Array.isArray(lamumuTokens) && lamumuTokens.length) {
        const rarityFile = req.query.rarityFile ? String(req.query.rarityFile) : path.join(process.cwd(), 'output', 'lamumu-rarity.json');
        let rarityData = null;
        try {
          if (/^https?:\/\//i.test(rarityFile)) {
            const resp = await fetch(rarityFile, { headers: { 'accept': 'application/json' } });
            if (resp.ok) {
              const text = await resp.text();
              try { rarityData = JSON.parse(text); } catch {}
            }
          } else {
            rarityData = JSON.parse(await fs.readFile(rarityFile, 'utf8'));
          }
        } catch {}
        let rarityMap = null; // token_id -> { rank?, score? }
        if (rarityData) {
          if (Array.isArray(rarityData)) {
            rarityMap = new Map();
            for (const r of rarityData) {
              if (!r || typeof r !== 'object') continue;
              const tid = r.token_id != null ? String(r.token_id) : (r.id != null ? String(r.id) : undefined);
              if (!tid) continue;
              const rank = toNumber(r.rank);
              const score = toNumber(r.score) ?? toNumber(r.rarity_score);
              rarityMap.set(tid, { rank, score });
            }
          } else if (typeof rarityData === 'object') {
            rarityMap = new Map();
            for (const [k, v] of Object.entries(rarityData)) {
              if (!k) continue; const tid = String(k);
              const rank = toNumber(v?.rank);
              const score = toNumber(v?.score) ?? toNumber(v?.rarity_score);
              rarityMap.set(tid, { rank, score });
            }
          }
        }
        const totalSupply = Number(process.env.LAMUMU_TOTAL_COUNT ?? 4500) || 4500;
        const rows = lamumuTokens.slice(0, 20).map(t => {
          const tid = t.token_id;
          const info = rarityMap?.get(String(tid));
          let rankVal = Number.isFinite(toNumber(t?.rank)) ? toNumber(t.rank) : (info?.rank);
          const rankTxt = (Number.isFinite(rankVal)) ? `Rank ${rankVal} / ${totalSupply}` : '—';
          const scoreTxt = (info?.score && Number.isFinite(info.score)) ? info.score.toLocaleString('en-US', { maximumFractionDigits: 4 }) : '—';
          return `<div class="row" style="justify-content:space-between"><div>#${String(tid)}</div><div class="hint">${rankTxt}${info?.score?` • Score ${scoreTxt}`:''}</div></div>`;
        }).join('');
        const hasAnyApiRank = lamumuTokens.some(t => Number.isFinite(toNumber(t?.rank)));
        lamumuRarityBlock = `
          <div class="card" style="margin-top:10px">
            <div class="label">Lamumu holdings${lamumuTokens.length>20?` (first 20 shown)`:''}</div>
            <div style="margin-top:8px; display:flex; flex-direction:column; gap:6px">${rows || '<div class="hint">No tokens found</div>'}</div>
            ${( !rarityData && !hasAnyApiRank ) ? '<div class="hint" style="margin-top:8px">Rarity data not available. Provide output/lamumu-rarity.json to show ranks.</div>' : ''}
          </div>`;
      }
    } catch {}
    resultBlock = `
      <div class="card" style="margin-top:14px">
        <div class="title">Result</div>
        <div class="row" style="margin-top:10px">
          <div class="card" style="flex:1">
            <div class="label">Lamumu count</div>
            <div class="title">${fmt(lamumuCount)}</div>
          </div>
          <div class="card" style="flex:1">
            <div class="label">Aura (xp_points)</div>
            <div class="title">${fmt(aura)}</div>
          </div>
          <div class="card" style="flex:1">
            <div class="label">Common activity points</div>
            <div class="title">${fmt(userActivityPoints)}</div>
            <div class="hint">threads + comments + upvotes</div>
          </div>
        </div>
    ${(() => { const out = filterUserMsgs(msgs); return out.length ? `<div class="hint" style="margin-top:8px">${out.map(m => esc(m)).join('<br/>')}</div>` : ''; })()}
  </div>` + lamumuRarityBlock + allocationBlock;
  }

  const html = `<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Common Checker</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
      <style>
        :root { --bg:#0b1220; --card:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --accent:#22d3ee; --line:#1e293b; }
        *{box-sizing:border-box}
        body{margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; background:var(--bg); color:var(--text)}
  header{padding:20px 22px; border-bottom:1px solid var(--line); text-align:center}
        .topnav{display:flex; gap:10px; align-items:center; justify-content:center; flex-wrap:wrap}
        .topnav .sep{color:var(--muted)}
  .btn{display:inline-block; padding:8px 12px; border:1px solid var(--line); border-radius:10px; background:transparent; color:var(--text); text-decoration:none; font-size:14px}
        .btn:hover{border-color:var(--accent); color:var(--accent)}
        .btn.current{pointer-events:none; opacity:0.8}
  .container{padding:16px 18px; max-width:1000px; margin:0 auto}
  .card{background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px}
  .label{color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:0.06em}
  .title{font-size:24px; font-weight:700; margin:0 0 10px}
  .row{display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:10px}
  input[type="text"]{flex:1; min-width:300px; padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:#0f172a; color:var(--text); font-size:14px}
  .hint{color:var(--muted); font-size:13px; margin-top:6px}
  .notice{border:2px solid var(--accent); background:rgba(34,211,238,0.12); color:var(--text); padding:14px 16px; border-radius:12px; font-size:15px; font-weight:700;}
  .notice .em{color:var(--accent)}
      </style>
    </head>
    <body>
      <header>
        <div class="topnav">
          <a class="btn" href="/summary">Common Stats</a>
          <span class="sep">•</span>
          <a class="btn" href="/users">Users stats»</a>
          <span class="sep">•</span>
          
          <a class="btn current" href="/common-checker">Common Checker</a>
        </div>
        <div class="meta" style="color:#ffffff; font-size:12px;">Created by <a href="https://x.com/0xMelkoreth" target="_blank" rel="noopener" style="color:#ffffff; text-decoration:underline">Melkor.eth</a></div>
      </header>
      <div class="container">
        <div class="card">
          <div class="title">Common Checker</div>
          <div class="label">Enter EVM address</div>
          <form method="GET" action="${esc(req.path)}" class="row">
            <input type="text" name="q" value="${esc(q)}" placeholder="e.g. 0xabc..." />
            <button class="btn" type="submit">Check</button>
          </form>
          
        </div>
        ${priceBlock}
    ${perUnitBlock}
        ${resultBlock}
      </div>
    </body>
  </html>`;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  return res.status(200).send(html);
}

// Canonical pages for Common Checker
app.get('/xps-ranked/common-checker-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/common-checker' + q);
});
app.get('/xps-ranked/avg-allocation-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/common-checker' + q);
});

// GET /xps-ranked/summary-html
// profile-xp.json ve profile-activity.json dosyalarından toplamları hesaplar ve HTML sayfası döner.
// Query: xpFile (default output/profile-xp.json), activityFile (default output/profile-activity.json),
//        onlyOk=true|false, outFile (default output/summary.html), writeFile=true|false
app.get('/xps-ranked/summary-html', async (req, res) => {
  try {
    const xpFile = req.query.xpFile ? String(req.query.xpFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
  const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'summary.html');
  const writeFile = String(req.query.writeFile ?? 'true').toLowerCase() !== 'false';
  const canWrite = writeFile && !(process.env.VERCEL || process.env.NODE_ENV === 'production');
    const threshold = Number(req.query.threshold ?? 1000) || 1000;
    const useSupabase = String(req.query.useSupabase ?? 'true').toLowerCase() !== 'false';

    // Helpers
    async function readJsonSafe(file) {
      try {
        const txt = await fs.readFile(file, 'utf8');
        return JSON.parse(txt);
      } catch {
        return undefined;
      }
    }

    function sumXpPoints(data) {
      const results = Array.isArray(data?.results) ? data.results : [];
      let total = 0;
      let counted = 0;
      let maxXp = 0;
      let overThreshold = 0;
      for (const r of results) {
        if (!r || typeof r !== 'object') continue;
        if (onlyOk && r.ok === false) continue;
        const n = toNumber(r.xp_points);
        if (n === undefined) continue;
        total += n;
        counted++;
        if (n > maxXp) maxXp = n;
        if (n > threshold) overThreshold++;
      }
      const avg = counted > 0 ? total / counted : 0;
      return { total, counted, avg, max: maxXp, overThreshold };
    }

    function sumActivity(data) {
      const results = Array.isArray(data?.results) ? data.results : [];
      let addresses = 0;
      let threads = 0;
      let comments = 0;
      let totalUpvotes = 0;
      let commentThreads = 0;
      let counted = 0;
      for (const r of results) {
        if (!r || typeof r !== 'object') continue;
        if (onlyOk && r.ok === false) continue;
        addresses += toNumber(r.addresses) || 0;
        threads += toNumber(r.threads) || 0;
        comments += toNumber(r.comments) || 0;
        totalUpvotes += toNumber(r.totalUpvotes) || 0;
        commentThreads += toNumber(r.commentThreads) || 0;
        counted++;
      }
      return { addresses, threads, comments, totalUpvotes, commentThreads, counted };
    }

  let xp = { total: 0, counted: 0, avg: 0, max: 0, overThreshold: 0 };
  let act = { addresses: 0, threads: 0, comments: 0, totalUpvotes: 0, commentThreads: 0, counted: 0 };
  let summaryRow = null;
  let zeroAuraCountCalc = null;

    if (useSupabase) {
      // Pull from Supabase tables (default anon key from env)
      const sb = getSupabase();
      // First try summary_stats table for a single-row snapshot
      const { data: sumData, error: sumErr } = await sb.from('summary_stats').select('*').eq('id', 1).maybeSingle();
      if (!sumErr && sumData) {
        summaryRow = sumData;
      }
      // xp (include user_id to optionally filter activity with onlyOk)
      const xpRows = [];
      const pageSize = 2000;
      let from = 0;
      while (true) {
        const to = from + pageSize - 1;
        const { data, error } = await sb.from('user_xp').select('user_id, xp_points, ok').range(from, to);
        if (error) throw error;
        const arr = Array.isArray(data) ? data : [];
        xpRows.push(...arr);
        if (arr.length < pageSize) break;
        from += pageSize;
        if (from > 200000) break;
      }
      if (!summaryRow) {
        const xpDataLike = { results: xpRows.map((r) => ({ xp_points: r.xp_points, ok: r.ok })) };
        xp = sumXpPoints(xpDataLike);
        // compute zero aura users from xpRows when summary snapshot is not available
        zeroAuraCountCalc = xpRows.reduce((acc, r) => {
          if (!r || (onlyOk && r.ok !== true)) return acc;
          const n = toNumber(r.xp_points);
          return acc + (n === 0 ? 1 : 0);
        }, 0);
      }

      // activity (no 'ok' column; filter by xp.ok if onlyOk=true)
      const okIds = new Set();
      if (onlyOk) {
        for (const r of xpRows) {
          if (r && r.ok === true && r.user_id != null) okIds.add(Number(r.user_id));
        }
      }
      const actRows = [];
      from = 0;
      while (true) {
        const to = from + pageSize - 1;
        const { data, error } = await sb.from('user_activity').select('user_id, addresses, threads, comments, total_upvotes, comment_threads').range(from, to);
        if (error) throw error;
        const arr = Array.isArray(data) ? data : [];
        actRows.push(...arr);
        if (arr.length < pageSize) break;
        from += pageSize;
        if (from > 200000) break;
      }
      if (!summaryRow) {
        const actFiltered = onlyOk ? actRows.filter((r) => okIds.has(Number(r.user_id))) : actRows;
        const actDataLike = { results: actFiltered.map((r) => ({ addresses: r.addresses, threads: r.threads, comments: r.comments, totalUpvotes: r.total_upvotes, commentThreads: r.comment_threads, ok: true })) };
        act = sumActivity(actDataLike);
      }
    } else {
      // Fallback to file-based
      const xpData = await readJsonSafe(xpFile);
      const activityData = await readJsonSafe(activityFile);
      xp = xpData ? sumXpPoints(xpData) : xp;
      act = activityData ? sumActivity(activityData) : act;
      if (xpData && Array.isArray(xpData.results)) {
        zeroAuraCountCalc = xpData.results.reduce((acc, r) => {
          if (!r || (onlyOk && r.ok === false)) return acc;
          const n = toNumber(r.xp_points);
          return acc + (n === 0 ? 1 : 0);
        }, 0);
      }
    }

  const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : String(n ?? ''));

  const usersCount = summaryRow?.total_users ?? ((act && act.counted) ? act.counted : (xp && xp.counted ? xp.counted : 0));
  const totalAura = summaryRow?.total_aura ?? xp.total;
  const maxAura = summaryRow?.max_aura ?? xp.max;
  const overTh = summaryRow?.users_over_1000 ?? xp.overThreshold;
  const zeroAuraUsers = summaryRow?.zero_aura_count ?? zeroAuraCountCalc ?? 0;
  const sumAddresses = summaryRow?.total_addresses ?? act.addresses;
  const sumThreads = summaryRow?.total_threads ?? act.threads;
  const sumComments = summaryRow?.total_comments ?? act.comments;
  const sumUpvotes = summaryRow?.total_upvotes ?? act.totalUpvotes;
  const sumCommentThreads = summaryRow?.total_comment_threads ?? act.commentThreads;
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Common Stats</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0b1220; --card:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --accent:#22d3ee; --line:#1e293b; }
    *{box-sizing:border-box}
    body{margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; background:var(--bg); color:var(--text)}
  header{padding:clamp(16px, 3vw, 28px) 20px; border-bottom:1px solid var(--line); text-align:center}
  h1{margin:0; font-size:clamp(18px, 2.5vw, 26px); letter-spacing:0.2px}
  .topnav{display:flex; gap:10px; align-items:center; justify-content:center; flex-wrap:wrap}
  .topnav .sep{color:var(--muted)}
  .btn{display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--text); text-decoration:none; font-size:13px}
  .btn:hover{border-color:var(--accent); color:var(--accent)}
  .btn.current{pointer-events:none; opacity:0.8}
    .meta{color:var(--muted); font-size:12px; margin-top:6px}
    .container{padding:clamp(12px, 2.2vw, 20px); max-width:1200px; margin:0 auto}
    .grid{display:grid; grid-template-columns: repeat(auto-fit, minmax(230px,1fr)); gap:clamp(10px, 1.6vw, 18px)}
    .card{background:var(--card); border:1px solid var(--line); border-radius:14px; padding:clamp(12px, 2vw, 18px)}
    .label{color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.06em}
    .value{font-size:clamp(22px, 4.2vw, 34px); font-weight:700; margin-top:8px}
    a{color:var(--accent); text-decoration:none}
    @media (max-width: 520px){ .value{font-weight:700} }
  </style>
  </head>
  <body>
    <header>
  <div class="topnav">
  <a class="btn current" href="/summary">Common Stats</a>
    <span class="sep">•</span>
  <a class="btn" href="/users">Users stats»</a>
    <span class="sep">•</span>
  
  <a class="btn" href="/common-checker">Common Checker</a>
  </div>
  <div class="meta">Data as of 10.10.2025</div>
  <div class="meta" style="color:#ffffff; font-size:12px;">Created by <a href="https://x.com/0xMelkoreth" target="_blank" rel="noopener" style="color:#ffffff; text-decoration:underline">Melkor.eth</a></div>
    </header>
    <div class="container">
      <div class="grid">
        <div class="card">
          <div class="label">Total Users</div>
          <div class="value">${fmt(usersCount)}</div>
        </div>
        <div class="card">
          <div class="label">Total Aura</div>
          <div class="value">${fmt(totalAura)}</div>
        </div>
        <div class="card">
          <div class="label">Max Aura</div>
          <div class="value">${fmt(maxAura)}</div>
        </div>
        <div class="card">
          <div class="label">Users > ${fmt(threshold)} Aura</div>
          <div class="value">${fmt(overTh)}</div>
        </div>
        <div class="card">
          <div class="label">Zero Aura Users</div>
          <div class="value">${fmt(zeroAuraUsers)}</div>
        </div>
        <div class="card">
          <div class="label">Total coin created by users</div>
          <div class="value">${fmt(sumAddresses)}</div>
        </div>
        <div class="card">
          <div class="label">Threads</div>
          <div class="value">${fmt(sumThreads)}</div>
        </div>
        <div class="card">
          <div class="label">Comments</div>
          <div class="value">${fmt(sumComments)}</div>
        </div>
        <div class="card">
          <div class="label">Total Upvotes</div>
          <div class="value">${fmt(sumUpvotes)}</div>
        </div>
        <div class="card">
          <div class="label">Comment Threads</div>
          <div class="value">${fmt(sumCommentThreads)}</div>
        </div>
      </div>
    </div>
  </body>
  </html>`;

    if (canWrite) {
      await fs.mkdir(path.dirname(outFile), { recursive: true });
      await fs.writeFile(outFile, html, 'utf8');
    }

    res.setHeader('content-type', 'text/html; charset=utf-8');
    return res.status(200).send(html);
  } catch (err) {
    return res.status(500).json({ error: 'Summary HTML failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/users-html
// Lists users from concat.json with avatar, username, id, Aura (xp_points from profile-xp.json),
// and activity counts (addresses/threads/comments/upvotes/commentThreads) from profile-activity.json.
// Query: concatFile (default output/concat.json), xpFile (default output/profile-xp.json),
//        activityFile (default output/profile-activity.json), onlyOk=true|false,
//        page (default 1), limit (default 50), sortBy=xp|id|username (default xp), order=desc|asc (default desc),
//        outFile (default output/users.html), writeFile=true|false
app.get('/xps-ranked/users-html', async (req, res) => {
  try {
  const concatFile = req.query.concatFile ? String(req.query.concatFile) : path.join(process.cwd(), 'output', 'concat.json');
  const xpFile = req.query.xpFile ? String(req.query.xpFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
  const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
  const lamumuFile = req.query.lamumuFile ? String(req.query.lamumuFile) : path.join(process.cwd(), 'output', 'profile_stats_lamumu.json');
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
    const page = Math.max(1, Number(req.query.page ?? 1) || 1);
    const limit = Math.max(1, Math.min(200, Number(req.query.limit ?? 50) || 50));
  const sortBy = (req.query.sortBy ? String(req.query.sortBy) : 'xp').toLowerCase();
  const order = (req.query.order ? String(req.query.order) : 'desc').toLowerCase();
  const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'users.html');
  const writeFile = String(req.query.writeFile ?? 'true').toLowerCase() !== 'false';
  const canWrite = writeFile && !(process.env.VERCEL || process.env.NODE_ENV === 'production');
  const q = (req.query.q ? String(req.query.q) : '').trim();

    async function readJsonSafe(file) {
      try {
        const txt = await fs.readFile(file, 'utf8');
        return JSON.parse(txt);
      } catch {
        return undefined;
      }
    }

    // Data source: Supabase (default) or file-based (useSupabase=false)
    const useSupabase = String(req.query.useSupabase ?? 'true').toLowerCase() !== 'false';
    let concatArr, xpResults, actResults;
    if (useSupabase) {
      // Sunucu taraflı paging/sort/filter. Artık tek kaynak user_profile_stats.
      const sb = getSupabase();
      const effectiveOrder = (sortBy === 'xp') ? 'desc' : order; // xp için her zaman azalan
      const fromIdx = (page - 1) * limit;
      const toIdx = fromIdx + limit - 1;

      // Ana sorgu: user_profile_stats + users (left join) — username ve fallback avatar için
      const baseSelect = 'user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, lamumu_count, users!left(id, username, avatar_url)';
      const fallbackSelect = 'user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, users!left(id, username, avatar_url)';
      let lamumuExists = true;
      let qStats = sb
        .from('user_profile_stats')
        .select(baseSelect, { count: 'exact' });

      // Search:
      // - q tamamen rakamsa user_id eşitliği
      // - aksi halde display_name veya users.username üzerinde ILIKE
      if (q) {
        const digits = q.replace(/[^0-9]/g, '');
        if (digits && digits.length === q.length) {
          qStats = qStats.eq('user_id', digits);
        } else {
          const like = `%${q}%`;
          // display_name üzerinde arama (user_profile_stats.display_name)
          qStats = qStats.ilike('display_name', like);
        }
      }

  // xp_points null olmayanlar
      qStats = qStats.not('xp_points', 'is', null);

      // Sıralama: xp_points DESC zorunlu, eşitlikte user_id ASC bağlaç
      const ascXp = (effectiveOrder === 'asc');
      qStats = qStats
        .order('xp_points', { ascending: ascXp, nullsFirst: false })
        .order('user_id', { ascending: !ascXp });

      // Sayfalama
      qStats = qStats.range(fromIdx, toIdx);

      let { data: statsRows, count, error: statsErr } = await qStats;
      if (statsErr && /column .*lamumu_count.* does not exist|42703/i.test(statsErr.message || '')) {
        lamumuExists = false;
        // re-run without lamumu_count
        let q2 = sb
          .from('user_profile_stats')
          .select(fallbackSelect, { count: 'exact' })
          .not('xp_points', 'is', null)
          .order('xp_points', { ascending: (effectiveOrder === 'asc'), nullsFirst: false })
          .order('user_id', { ascending: !(effectiveOrder === 'asc') })
          .range(fromIdx, toIdx);
        const res2 = await q2;
        statsErr = res2.error;
        statsRows = res2.data;
        count = res2.count;
      }
      if (statsErr) throw statsErr;

      const baseRows = Array.isArray(statsRows) ? statsRows : [];

      // Render veri modeli
      const users = baseRows.map((r) => {
        const userObj = Array.isArray(r.users) ? r.users[0] : r.users;
        const id = Number(r.user_id ?? userObj?.id);
        const name = String(r.display_name || userObj?.username || `user-${id}`);
        const avatar = String(r.avatar_url || userObj?.avatar_url || '');
        const xp = toNumber(r?.xp_points);
        const addresses = toNumber(r?.addresses) || 0;
        const threads = toNumber(r?.threads) || 0;
        const comments = toNumber(r?.comments) || 0;
        const totalUpvotes = toNumber(r?.total_upvotes) || 0;
        const commentThreads = toNumber(r?.comment_threads) || 0;
        const lamumu = lamumuExists ? (toNumber(r?.lamumu_count) || 0) : undefined;
        return { id, name, avatar, xp, addresses, threads, comments, totalUpvotes, commentThreads, lamumu };
      });

      // Toplam ve sayfa bilgisi
      const total = count ?? users.length;
      const totalPages = Math.max(1, Math.ceil(total / limit));
      const curPage = Math.min(page, totalPages);

      const esc = (s) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
      const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : (n === undefined || n === null ? '—' : String(n)));

      function buildLink(targetPage) {
        const params = new URLSearchParams();
        params.set('page', String(targetPage));
        params.set('limit', String(limit));
        params.set('sortBy', sortBy);
        params.set('order', effectiveOrder);
        params.set('onlyOk', String(onlyOk));
        if (q) params.set('q', q);
        return `/users?${params.toString()}`;
      }

      const rowsHtml = users.map((u, idx) => `
      <tr>
        <td class="cell rank" data-label="Rank">${fmt(fromIdx + idx + 1)}</td>
        <td class="cell id" data-label="ID">${fmt(u.id)}</td>
        <td class="cell user" data-label="User">
          <div class="userbox">
            ${u.avatar ? `<img class="avatar" src="${esc(u.avatar)}" alt="${esc(u.name)}" onerror="this.style.display='none'" />` : ''}
            <div class="meta" style="min-width:0">
              <div class="name" style="word-break:break-word; overflow-wrap:anywhere">${esc(u.name)}</div>
            </div>
          </div>
        </td>
        <td class="cell xp" data-label="Aura">${fmt(u.xp)}</td>
        <td class="cell addresses" data-label="Total coin created by users">${fmt(u.addresses)}</td>
        <td class="cell threads" data-label="Threads">${fmt(u.threads)}</td>
        <td class="cell comments" data-label="Comments">${fmt(u.comments)}</td>
        <td class="cell upvotes" data-label="Total Upvotes">${fmt(u.totalUpvotes)}</td>
  <td class="cell cthreads" data-label="Comment Threads">${fmt(u.commentThreads)}</td>
      </tr>`).join('');

      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Common Users</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0b1220; --card:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --accent:#22d3ee; --line:#1e293b; }
    *{box-sizing:border-box}
    body{margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; background:var(--bg); color:var(--text)}
    header{padding:16px 20px; border-bottom:1px solid var(--line); text-align:center}
    h1{margin:0; font-size:22px; letter-spacing:0.2px}
    .topnav{display:flex; gap:10px; align-items:center; justify-content:center; flex-wrap:wrap}
    .topnav .sep{color:var(--muted)}
    .btn{display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--text); text-decoration:none; font-size:13px}
    .btn:hover{border-color:var(--accent); color:var(--accent)}
    .btn.current{pointer-events:none; opacity:0.8}
    .container{padding:14px 16px; max-width:1280px; margin:0 auto}
    .toolbar{display:flex; align-items:center; justify-content:space-between; color:var(--muted); font-size:12px; margin-bottom:10px}
    .pager a{color:var(--accent); text-decoration:none; margin:0 6px}
    .table-wrap{width:100%; overflow-x:auto}
    table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden; min-width:720px}
    thead th{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; padding:10px; text-align:left; background:#0d1526}
    tbody td{padding:10px; border-top:1px solid var(--line)}
    .userbox{display:flex; align-items:center; gap:10px}
    .avatar{width:36px; height:36px; border-radius:50%; object-fit:cover; border:1px solid var(--line); background:#1e293b}
    .name{font-weight:600}
    .sub{color:var(--muted); font-size:11px}
    .cell.xp,.cell.addresses,.cell.threads,.cell.comments,.cell.upvotes,.cell.cthreads{font-variant-numeric:tabular-nums}
    .pager{margin-top:12px; text-align:center}
    @media (max-width:760px){ .sub{display:none} thead{display:none} table,tbody,tr,td{display:block;width:100%} tbody td{border:none; padding:8px 10px} tr{border:1px solid var(--line); border-radius:12px; margin-bottom:10px; background:var(--card)} .cell{display:flex; justify-content:space-between; gap:10px} .cell::before{content:attr(data-label); color:var(--muted); flex:0 0 auto} .name{word-break:break-word; overflow-wrap:anywhere} }
  </style>
  </head>
  <body>
    <header>
      <div class="topnav">
  <a class="btn" href="/summary">Common Stats</a>
        <span class="sep">•</span>
  <a class="btn current" href="/users">Users stats»</a>
        <span class="sep">•</span>
        
  <a class="btn" href="/common-checker">Common Checker</a>
      </div>
  <div class="meta" style="color:#94a3b8; font-size:12px; margin-top:6px">Data as of 10.10.2025</div>
  <div class="meta" style="color:#ffffff; font-size:12px;">Created by <a href="https://x.com/0xMelkoreth" target="_blank" rel="noopener" style="color:#ffffff; text-decoration:underline">Melkor.eth</a></div>
    </header>
    <div class="container">
      <div class="toolbar">
        <div>
          <div>Totals: ${fmt(total)} • Page ${fmt(curPage)} / ${fmt(totalPages)} • Sorted by ${esc(sortBy)} ${esc(effectiveOrder)}${q ? ` • Search: ${esc(q)}` : ''}</div>
          <form method="GET" action="/users" style="display:flex; gap:6px; align-items:center; margin-top:6px">
            <input type="hidden" name="sortBy" value="${esc(sortBy)}" />
            <input type="hidden" name="order" value="${esc(effectiveOrder)}" />
            <input type="hidden" name="limit" value="${fmt(limit)}" />
            <input type="hidden" name="onlyOk" value="${onlyOk ? 'true' : 'false'}" />
            <input name="q" value="${esc(q)}" placeholder="Search by ID or username" style="padding:6px 8px; border:1px solid var(--line); border-radius:8px; background:#0f172a; color:var(--text); width:220px" />
            <button class="btn" type="submit">Search</button>
          </form>
        </div>
        <div class="pager">
          ${curPage > 1 ? `<a href="${buildLink(1)}">First</a>` : ''}
          ${curPage > 1 ? `<a href="${buildLink(curPage - 1)}">Prev</a>` : ''}
          ${curPage < totalPages ? `<a href="${buildLink(curPage + 1)}">Next</a>` : ''}
          ${curPage < totalPages ? `<a href="${buildLink(totalPages)}">Last</a>` : ''}
        </div>
      </div>
      <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Rank</th>
            <th>ID</th>
            <th>User</th>
            <th>Aura</th>
            <th>Total coin created by users</th>
            <th>Threads</th>
            <th>Comments</th>
            <th>Total Upvotes</th>
            <th>Comment Threads</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
      </div>
      <div class="pager">
        ${curPage > 1 ? `<a href="${buildLink(curPage - 1)}">Prev</a>` : ''}
        <span>Page ${fmt(curPage)} / ${fmt(totalPages)}</span>
        ${curPage < totalPages ? `<a href="${buildLink(curPage + 1)}">Next</a>` : ''}
      </div>
    </div>
  </body>
  </html>`;

      if (canWrite) {
        await fs.mkdir(path.dirname(outFile), { recursive: true });
        await fs.writeFile(outFile, html, 'utf8');
      }
      res.setHeader('content-type', 'text/html; charset=utf-8');
      return res.status(200).send(html);
    } else {
      // Default file-based source
      concatArr = await readJsonSafe(concatFile);
      if (!Array.isArray(concatArr)) {
        return res.status(400).json({ error: 'Invalid concat JSON: expected top-level array', concatFile });
      }
      const xpData = await readJsonSafe(xpFile);
      const actData = await readJsonSafe(activityFile);
      const lamData = await readJsonSafe(lamumuFile);
      xpResults = Array.isArray(xpData?.results) ? xpData.results : [];
      actResults = Array.isArray(actData?.results) ? actData.results : [];
      var lamMap = new Map();
      if (Array.isArray(lamData?.results)) {
        for (const r of lamData.results) {
          const uid = Number(r.user_id ?? r.userId ?? r.id);
          if (!Number.isFinite(uid)) continue;
          lamMap.set(uid, toNumber(r.lamumu_count) || 0);
        }
      }
    }

  // Build maps: userId -> xp / activity (file-based modda)
    const xpMap = new Map();
    for (const r of xpResults) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const id = Number(r.userId);
      if (!Number.isFinite(id)) continue;
      const xp = toNumber(r.xp_points);
      if (xp === undefined) continue;
      xpMap.set(id, xp);
    }
    const actMap = new Map();
    for (const r of actResults) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const id = Number(r.userId);
      if (!Number.isFinite(id)) continue;
      actMap.set(id, {
        addresses: toNumber(r.addresses) || 0,
        threads: toNumber(r.threads) || 0,
        comments: toNumber(r.comments) || 0,
        totalUpvotes: toNumber(r.totalUpvotes) || 0,
        commentThreads: toNumber(r.commentThreads) || 0,
      });
    }

    // Collect unique users from concat.json with basic fields
    const seen = new Set();
    const users = [];
    for (const item of concatArr) {
      if (!item || typeof item !== 'object') continue;
  const id = Number(item.user_id ?? item.userId ?? item.id);
      if (!Number.isFinite(id)) continue;
      if (seen.has(id)) continue;
      seen.add(id);
  const username = String(item.user_name ?? item.username ?? item.handle ?? '') || `user-${id}`;
  const avatar = String(item.avatar_url ?? item.avatar ?? '') || '';
      const xp = xpMap.has(id) ? xpMap.get(id) : undefined;
      const act = actMap.get(id) || { addresses: 0, threads: 0, comments: 0, totalUpvotes: 0, commentThreads: 0 };
      const lamumu = lamMap ? lamMap.get(id) : undefined;
      users.push({ id, username, avatar, xp, lamumu, ...act });
    }

    // Search filter (by id substring or username case-insensitive substring)
    let filtered = users;
    if (q) {
      const qLower = q.toLowerCase();
      const digits = q.replace(/[^0-9]/g, '');
      const hasDigits = digits.length > 0;
      filtered = users.filter((u) => {
        const nameHit = (u.username || '').toLowerCase().includes(qLower);
        const idHit = hasDigits ? String(u.id).includes(digits) : false;
        return nameHit || idHit;
      });
    }

    // Sort
    const dir = order === 'asc' ? 1 : -1;
    filtered.sort((a, b) => {
      let va, vb;
      if (sortBy === 'id') { va = a.id; vb = b.id; }
      else if (sortBy === 'username') { va = String(a.username).toLowerCase(); vb = String(b.username).toLowerCase(); }
      else { va = a.xp ?? -1; vb = b.xp ?? -1; } // default xp
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });

    // Pagination
    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const curPage = Math.min(page, totalPages);
    const start = (curPage - 1) * limit;
    const slice = filtered.slice(start, start + limit);

    const esc = (s) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : (n === undefined || n === null ? '—' : String(n)));

    // Build pagination URLs preserving base path and selected sort/order/limit
    function buildLink(targetPage) {
      const params = new URLSearchParams();
      params.set('page', String(targetPage));
      params.set('limit', String(limit));
      params.set('sortBy', sortBy);
      params.set('order', order);
      params.set('onlyOk', String(onlyOk));
      if (q) params.set('q', q);
  return `/users?${params.toString()}`;
    }

    const rows = slice.map((u, idx) => `
      <tr>
        <td class="cell rank" data-label="Rank">${fmt(start + idx + 1)}</td>
        <td class="cell id" data-label="ID">${fmt(u.id)}</td>
        <td class="cell user" data-label="User">
          <div class="userbox">
            ${u.avatar ? `<img class="avatar" src="${esc(u.avatar)}" alt="${esc(u.username)}" onerror="this.style.display='none'" />` : ''}
            <div class="meta" style="min-width:0">
              <div class="name" style="word-break:break-word; overflow-wrap:anywhere">${esc(u.username)}</div>
            </div>
          </div>
        </td>
        <td class="cell xp" data-label="Aura">${fmt(u.xp)}</td>
        <td class="cell addresses" data-label="Total coin created by users">${fmt(u.addresses)}</td>
        <td class="cell threads" data-label="Threads">${fmt(u.threads)}</td>
        <td class="cell comments" data-label="Comments">${fmt(u.comments)}</td>
        <td class="cell upvotes" data-label="Total Upvotes">${fmt(u.totalUpvotes)}</td>
  <td class="cell cthreads" data-label="Comment Threads">${fmt(u.commentThreads)}</td>
      </tr>`).join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Common Users</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0b1220; --card:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --accent:#22d3ee; --line:#1e293b; }
    *{box-sizing:border-box}
    body{margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; background:var(--bg); color:var(--text)}
    header{padding:16px 20px; border-bottom:1px solid var(--line); text-align:center}
    h1{margin:0; font-size:22px; letter-spacing:0.2px}
    .topnav{display:flex; gap:10px; align-items:center; justify-content:center; flex-wrap:wrap}
    .topnav .sep{color:var(--muted)}
    .btn{display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--text); text-decoration:none; font-size:13px}
    .btn:hover{border-color:var(--accent); color:var(--accent)}
    .btn.current{pointer-events:none; opacity:0.8}
    .container{padding:14px 16px; max-width:1280px; margin:0 auto}
    .toolbar{display:flex; align-items:center; justify-content:space-between; color:var(--muted); font-size:12px; margin-bottom:10px}
    .pager a{color:var(--accent); text-decoration:none; margin:0 6px}
    .table-wrap{width:100%; overflow-x:auto}
    table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden; min-width:720px}
    thead th{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; padding:10px; text-align:left; background:#0d1526}
    tbody td{padding:10px; border-top:1px solid var(--line)}
    .userbox{display:flex; align-items:center; gap:10px}
    .avatar{width:36px; height:36px; border-radius:50%; object-fit:cover; border:1px solid var(--line); background:#1e293b}
    .name{font-weight:600}
    .sub{color:var(--muted); font-size:11px}
    .cell.xp,.cell.addresses,.cell.threads,.cell.comments,.cell.upvotes,.cell.cthreads{font-variant-numeric:tabular-nums}
    .pager{margin-top:12px; text-align:center}
    @media (max-width:760px){ .sub{display:none} thead{display:none} table,tbody,tr,td{display:block;width:100%} tbody td{border:none; padding:8px 10px} tr{border:1px solid var(--line); border-radius:12px; margin-bottom:10px; background:var(--card)} .cell{display:flex; justify-content:space-between; gap:10px} .cell::before{content:attr(data-label); color:var(--muted); flex:0 0 auto} .name{word-break:break-word; overflow-wrap:anywhere} }
  </style>
  </head>
  <body>
    <header>
      <div class="topnav">
  <a class="btn" href="/summary">Common Stats</a>
        <span class="sep">•</span>
  <a class="btn current" href="/users">Users stats»</a>
        <span class="sep">•</span>
        
  <a class="btn" href="/common-checker">Common Checker</a>
      </div>
  <div class="meta" style="color:#94a3b8; font-size:12px; margin-top:6px">Data as of 10.10.2025</div>
      <div class="meta" style="color:#ffffff; font-size:12px;">Created by <a href="https://x.com/0xMelkoreth" target="_blank" rel="noopener" style="color:#ffffff; text-decoration:underline">Melkor.eth</a></div>
    </header>
    <div class="container">
      <div class="toolbar">
        <div>
          <div>Totals: ${fmt(total)} • Page ${fmt(curPage)} / ${fmt(totalPages)} • Sorted by ${esc(sortBy)} ${esc(order)}${q ? ` • Search: ${esc(q)}` : ''}</div>
          <form method="GET" action="/users" style="display:flex; gap:6px; align-items:center; margin-top:6px">
            <input type="hidden" name="sortBy" value="${esc(sortBy)}" />
            <input type="hidden" name="order" value="${esc(order)}" />
            <input type="hidden" name="limit" value="${fmt(limit)}" />
            <input type="hidden" name="onlyOk" value="${onlyOk ? 'true' : 'false'}" />
            <input name="q" value="${esc(q)}" placeholder="Search by ID or username" style="padding:6px 8px; border:1px solid var(--line); border-radius:8px; background:#0f172a; color:var(--text); width:220px" />
            <button class="btn" type="submit">Search</button>
          </form>
        </div>
        <div class="pager">
          ${curPage > 1 ? `<a href="${buildLink(1)}">First</a>` : ''}
          ${curPage > 1 ? `<a href="${buildLink(curPage - 1)}">Prev</a>` : ''}
          ${curPage < totalPages ? `<a href="${buildLink(curPage + 1)}">Next</a>` : ''}
          ${curPage < totalPages ? `<a href="${buildLink(totalPages)}">Last</a>` : ''}
        </div>
      </div>
      <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Rank</th>
            <th>ID</th>
            <th>User</th>
            <th>Aura</th>
            <th>Total coin created by users</th>
            <th>Threads</th>
            <th>Comments</th>
            <th>Total Upvotes</th>
            <th>Comment Threads</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
      </div>
      <div class="pager">
        ${curPage > 1 ? `<a href="${buildLink(curPage - 1)}">Prev</a>` : ''}
        <span>Page ${fmt(curPage)} / ${fmt(totalPages)}</span>
        ${curPage < totalPages ? `<a href="${buildLink(curPage + 1)}">Next</a>` : ''}
      </div>
    </div>
  </body>
  </html>`;

    if (writeFile) {
      await fs.mkdir(path.dirname(outFile), { recursive: true });
      await fs.writeFile(outFile, html, 'utf8');
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    return res.status(200).send(html);
  } catch (err) {
    return res.status(500).json({ error: 'Users HTML failure', message: err?.message || String(err) });
  }
});

// Lamumu holder stats — same table as users but sorted by lamumu_count desc
app.get('/xps-ranked/lamumu-holders-html', async (req, res) => {
  try {
    const page = Math.max(1, toNumber(req.query.page) || 1);
    const limit = Math.min(200, Math.max(10, toNumber(req.query.limit) || 50));
    const order = (String(req.query.order || 'desc').toLowerCase() === 'asc') ? 'asc' : 'desc';
    const useSupabase = String(req.query.useSupabase || '').toLowerCase() === 'true' || process.env.SUPABASE_URL;
    const q = (req.query.q ? String(req.query.q) : '').trim();

    const concatFile = req.query.concatFile ? String(req.query.concatFile) : path.join(process.cwd(), 'output', 'concat.json');
    const xpFile = req.query.xpFile ? String(req.query.xpFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const lamumuFile = req.query.lamumuFile ? String(req.query.lamumuFile) : path.join(process.cwd(), 'output', 'profile_stats_lamumu.json');

    let users = [];
    let totalCount = 0;
    const fromIdx = (page - 1) * limit;
    const toIdx = fromIdx + limit - 1;

    if (useSupabase) {
      const sb = getSupabase();
      // Try to select and order by lamumu_count; gracefully fallback if column is missing
      const baseSelect = 'user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, lamumu_count, users!left(id, username, avatar_url)';
      const fallbackSelect = 'user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, users!left(id, username, avatar_url)';
      let lamumuExists = true;

      let qStats = sb
        .from('user_profile_stats')
        .select(baseSelect, { count: 'exact' })
        .not('xp_points', 'is', null)
        .gte('lamumu_count', 1)
        .order('lamumu_count', { ascending: (order === 'asc'), nullsFirst: false })
        .order('user_id', { ascending: !(order === 'asc') })
        .range(fromIdx, toIdx);

      // Apply search (q is the search string)
      if (q) {
        const digits = q.replace(/[^0-9]/g, '');
        if (digits && digits.length === q.length) {
          qStats = qStats.eq('user_id', digits);
        } else {
          const like = `%${q}%`;
          qStats = qStats.ilike('display_name', like);
        }
      }

      let { data, count, error } = await qStats;
      if (error && /column .*lamumu_count.* does not exist|42703/i.test(error.message || '')) {
        lamumuExists = false;
        let q2 = sb
          .from('user_profile_stats')
          .select(fallbackSelect, { count: 'exact' })
          .not('xp_points', 'is', null)
          .order('xp_points', { ascending: (order === 'asc'), nullsFirst: false })
          .order('user_id', { ascending: !(order === 'asc') })
          .range(fromIdx, toIdx);
        if (q) {
          const digits = q.replace(/[^0-9]/g, '');
          if (digits && digits.length === q.length) {
            q2 = q2.eq('user_id', digits);
          } else {
            const like = `%${q}%`;
            q2 = q2.ilike('display_name', like);
          }
        }
        const r2 = await q2;
        data = r2.data; count = r2.count; error = r2.error;
      }
      if (error) throw error;

      totalCount = count || 0;
      users = (data || []).map((r) => {
        const u = Array.isArray(r.users) ? r.users[0] : r.users;
        const id = Number(r.user_id ?? u?.id);
        const name = String(r.display_name || u?.username || `user-${id}`);
        const avatar = String(r.avatar_url || u?.avatar_url || '');
        const xp = toNumber(r?.xp_points);
        const addresses = toNumber(r?.addresses) || 0;
        const threads = toNumber(r?.threads) || 0;
        const comments = toNumber(r?.comments) || 0;
        const totalUpvotes = toNumber(r?.total_upvotes) || 0;
        const commentThreads = toNumber(r?.comment_threads) || 0;
        const lamumu = lamumuExists ? (toNumber(r?.lamumu_count) || 0) : undefined;
        return { id, name, avatar, xp, addresses, threads, comments, totalUpvotes, commentThreads, lamumu };
      });
    } else {
      // File mode: read concat/xp/activity and optional lamumu json
      const concatArr = await readJsonSafe(concatFile);
      const xpData = await readJsonSafe(xpFile);
      const actData = await readJsonSafe(activityFile);
      const lamData = await readJsonSafe(lamumuFile);
      if (!Array.isArray(concatArr)) {
        return res.status(400).json({ error: 'Invalid concat JSON: expected top-level array', concatFile });
      }

      const xpMap = new Map();
      for (const r of (Array.isArray(xpData?.results) ? xpData.results : [])) {
        const uid = Number(r.user_id ?? r.userId ?? r.id);
        if (!Number.isFinite(uid)) continue;
        xpMap.set(uid, toNumber(r.xp_points ?? r.xp ?? 0));
      }
      const actMap = new Map();
      for (const r of (Array.isArray(actData?.results) ? actData.results : [])) {
        const uid = Number(r.user_id ?? r.userId ?? r.id);
        if (!Number.isFinite(uid)) continue;
        actMap.set(uid, {
          addresses: toNumber(r.addresses) || 0,
          threads: toNumber(r.threads) || 0,
          comments: toNumber(r.comments) || 0,
          totalUpvotes: toNumber(r.total_upvotes) || 0,
          commentThreads: toNumber(r.comment_threads) || 0,
        });
      }
      const lamMap = new Map();
      for (const r of (Array.isArray(lamData?.results) ? lamData.results : [])) {
        const uid = Number(r.user_id ?? r.userId ?? r.id);
        if (!Number.isFinite(uid)) continue;
        lamMap.set(uid, toNumber(r.lamumu_count) || 0);
      }

      const seen = new Set();
      for (const item of concatArr) {
        if (!item || typeof item !== 'object') continue;
        const id = Number(item.user_id ?? item.userId ?? item.id);
        if (!Number.isFinite(id)) continue;
        if (seen.has(id)) continue;
        seen.add(id);
        const username = String(item.user_name ?? item.username ?? item.handle ?? '') || `user-${id}`;
        const avatar = String(item.avatar_url ?? item.avatar ?? '') || '';
        const xp = xpMap.get(id);
        const act = actMap.get(id) || { addresses: 0, threads: 0, comments: 0, totalUpvotes: 0, commentThreads: 0 };
        const lamumu = lamMap.get(id) || 0;
        if ((lamumu ?? 0) >= 1) users.push({ id, name: username, avatar, xp, lamumu, ...act });
      }

  // Search filter similar to /users
      let filtered = users;
      if (q) {
        const qLower = q.toLowerCase();
        const digits = q.replace(/[^0-9]/g, '');
        const hasDigits = digits.length > 0;
        filtered = users.filter((u) => {
          const nameHit = (u.name || '').toLowerCase().includes(qLower);
          const idHit = hasDigits ? String(u.id).includes(digits) : false;
          return nameHit || idHit;
        });
      }
      filtered.sort((a, b) => (toNumber(b.lamumu) - toNumber(a.lamumu)) || (toNumber(b.xp) - toNumber(a.xp)) || (a.id - b.id));
      totalCount = filtered.length;
      users = filtered.slice(fromIdx, toIdx + 1);
    }

    const fmt = (v) => (v === undefined || v === null || Number.isNaN(v) ? '-' : String(v));
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    const rowsHtml = users.map((u, idx) => `
      <tr>
        <td class="cell rank" data-label="Rank">${fmt(fromIdx + idx + 1)}</td>
        <td class="cell id" data-label="ID">${fmt(u.id)}</td>
        <td class="cell user" data-label="User">
          <div class="userbox">
            ${u.avatar ? `<img class="avatar" src="${esc(u.avatar)}" alt="${esc(u.name)}" onerror="this.style.display='none'" />` : ''}
            <div class="meta" style="min-width:0">
              <div class="name" style="word-break:break-word; overflow-wrap:anywhere">${esc(u.name)}</div>
            </div>
          </div>
        </td>
        <td class="cell xp" data-label="Aura">${fmt(u.xp)}</td>
        <td class="cell lamumu" data-label="Lamumu count">${fmt(u.lamumu)}</td>
        <td class="cell addresses" data-label="Total coin created by users">${fmt(u.addresses)}</td>
        <td class="cell threads" data-label="Threads">${fmt(u.threads)}</td>
        <td class="cell comments" data-label="Comments">${fmt(u.comments)}</td>
        <td class="cell upvotes" data-label="Total Upvotes">${fmt(u.totalUpvotes)}</td>
        <td class="cell cthreads" data-label="Comment Threads">${fmt(u.commentThreads)}</td>
      </tr>`).join('');

    const totalPages = Math.max(1, Math.ceil(totalCount / limit));
  const nav = (label, p) => `<a href="?page=${p}&limit=${limit}&order=${order}${q ? `&q=${encodeURIComponent(q)}` : ''}${useSupabase ? '&useSupabase=true' : ''}" class="btn">${label}</a>`;
    const controls = `
      <div class="controls">
        <div>Page ${fmt(page)} / ${fmt(totalPages)} | Total ${fmt(totalCount)}</div>
        <div>
          ${page > 1 ? nav('Prev', page - 1) : ''}
          ${page < totalPages ? nav('Next', page + 1) : ''}
        </div>
      </div>`;

    const html = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Lamumu Holder Stats</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
      <style>
        :root { --bg:#0b1220; --card:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --accent:#22d3ee; --line:#1e293b; }
        *{box-sizing:border-box}
        body{margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; background:var(--bg); color:var(--text)}
        header{padding:16px 20px; border-bottom:1px solid var(--line); text-align:center}
        h1{margin:0; font-size:22px; letter-spacing:0.2px}
        .topnav{display:flex; gap:10px; align-items:center; justify-content:center; flex-wrap:wrap}
        .topnav .sep{color:var(--muted)}
        .btn{display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--text); text-decoration:none; font-size:13px}
        .btn:hover{border-color:var(--accent); color:var(--accent)}
        .btn.current{pointer-events:none; opacity:0.8}
        .container{padding:14px 16px; max-width:1280px; margin:0 auto}
        .toolbar{display:flex; align-items:center; justify-content:space-between; color:var(--muted); font-size:12px; margin-bottom:10px}
        .pager a{color:var(--accent); text-decoration:none; margin:0 6px}
        .table-wrap{width:100%; overflow-x:auto}
        table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden; min-width:720px}
        thead th{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; padding:10px; text-align:left; background:#0d1526}
        tbody td{padding:10px; border-top:1px solid var(--line)}
        .userbox{display:flex; align-items:center; gap:10px}
        .avatar{width:36px; height:36px; border-radius:50%; object-fit:cover; border:1px solid var(--line); background:#1e293b}
        .name{font-weight:600}
        .sub{color:var(--muted); font-size:11px}
        .cell.xp,.cell.addresses,.cell.threads,.cell.comments,.cell.upvotes,.cell.cthreads,.cell.lholder{font-variant-numeric:tabular-nums}
        .pager{margin-top:12px; text-align:center}
        @media (max-width:760px){ .sub{display:none} thead{display:none} table,tbody,tr,td{display:block;width:100%} tbody td{border:none; padding:8px 10px} tr{border:1px solid var(--line); border-radius:12px; margin-bottom:10px; background:var(--card)} .cell{display:flex; justify-content:space-between; gap:10px} .cell::before{content:attr(data-label); color:var(--muted); flex:0 0 auto} .name{word-break:break-word; overflow-wrap:anywhere} }
      </style>
    </head>
    <body>
      <header>
        <div class="topnav">
          <a class="btn" href="/summary">Common Stats</a>
          <span class="sep">•</span>
          <a class="btn" href="/users">Users stats»</a>
          <span class="sep">•</span>
          <a class="btn current" href="/users">Lamumu holder stats»</a>
          <span class="sep">•</span>
          <a class="btn" href="/common-checker">Common Checker</a>
        </div>
  <div class="meta" style="color:#94a3b8; font-size:12px; margin-top:6px">Sorted by Lamumu count (desc)</div>
  <div class="meta" style="color:#ffffff; font-size:12px;">Created by <a href="https://x.com/0xMelkoreth" target="_blank" rel="noopener" style="color:#ffffff; text-decoration:underline">Melkor.eth</a></div>
      </header>
      <div class="container">
        <div class="toolbar">
          <div>
            <div>Page ${fmt(page)} / ${fmt(totalPages)} • Total ${fmt(totalCount)}</div>
            <form method="GET" action="/users" style="display:flex; gap:6px; align-items:center; margin-top:6px">
              <input type="hidden" name="order" value="${order}" />
              <input type="hidden" name="limit" value="${limit}" />
              ${useSupabase ? '<input type="hidden" name="useSupabase" value="true" />' : ''}
              <input name="q" value="${esc(q)}" placeholder="Search by ID or username" style="padding:6px 8px; border:1px solid var(--line); border-radius:8px; background:#0f172a; color:var(--text); width:220px" />
              <button class="btn" type="submit">Search</button>
            </form>
          </div>
          <div class="pager">
            ${page > 1 ? nav('Prev', page - 1) : ''}
            ${page < totalPages ? nav('Next', page + 1) : ''}
          </div>
        </div>
        <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Rank</th>
              <th>ID</th>
              <th>User</th>
              <th>Aura</th>
              <th>Lamumu count</th>
              <th>Total coin created by users</th>
              <th>Threads</th>
              <th>Comments</th>
              <th>Total Upvotes</th>
              <th>Comment Threads</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
        </div>
        <div class="pager">
          ${page > 1 ? `<a href="?page=${page - 1}&limit=${limit}&order=${order}${useSupabase ? '&useSupabase=true' : ''}">Prev</a>` : ''}
          <span>Page ${fmt(page)} / ${fmt(totalPages)}</span>
          ${page < totalPages ? `<a href="?page=${page + 1}&limit=${limit}&order=${order}${useSupabase ? '&useSupabase=true' : ''}">Next</a>` : ''}
        </div>
      </div>
    </body>
    </html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(html);
  } catch (err) {
    console.error('lamumu-holders-html error:', err);
    return res.status(500).json({ error: String(err?.message || err) });
  }
});
// GET /xps-ranked/stats
// Reads a merged JSON array file (default output/concat.json), deduplicates by idKey, and reports counts
// for xp_points > threshold and xp_points == 0.
// Query params: jsonFile (path), idKey (default tries common keys), threshold (default 1000)
app.get('/xps-ranked/stats', async (req, res) => {
  try {
    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'concat.json');
    const idKey = req.query.idKey ? String(req.query.idKey) : undefined;
    const threshold = Number(req.query.threshold ?? 1000) || 1000;

    const text = await fs.readFile(jsonFile, 'utf8');
    const arr = JSON.parse(text);
    if (!Array.isArray(arr)) {
      return res.status(400).json({ error: 'Invalid concat JSON: root is not an array' });
    }

    const picked = new Map(); // id -> item with parsed xp
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const idInfo = getIdFromObject(item, idKey);
      if (!idInfo) continue;
      const id = `${idInfo.key}::${idInfo.value}`;
      const xpInfo = getXpPointsFromObject(item);
      const xp = xpInfo ? xpInfo.value : undefined;
      if (xp === undefined) continue;
      // Prefer the max xp if multiple entries per id
      const prev = picked.get(id);
      if (!prev || xp > prev.xp) {
        picked.set(id, { idKey: idInfo.key, idValue: idInfo.value, xp });
      }
    }

    let overThreshold = 0;
    let zeroXp = 0;
    for (const entry of picked.values()) {
      if (entry.xp > threshold) overThreshold++;
      if (entry.xp === 0) zeroXp++;
    }

    return res.json({ ok: true, totalPersons: picked.size, threshold, overThreshold, zeroXp, jsonFile, idKeyUsed: (idKey || (picked.size ? [...picked.values()][0].idKey : null)) });
  } catch (err) {
    return res.status(500).json({ error: 'Stats failure', message: err?.message || String(err) });
  }
});

// GET /xps-ranked/sum-xp
// Sums xp_points across unique users in a merged JSON file (default output/concat.json).
// Deduplicates by detected id key (or explicit idKey) and uses the maximum xp_points per user if duplicates exist.
// Query params: jsonFile (path), idKey (optional)
app.get('/xps-ranked/sum-xp', async (req, res) => {
  try {
    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'concat.json');
    const idKey = req.query.idKey ? String(req.query.idKey) : undefined;

    const text = await fs.readFile(jsonFile, 'utf8');
    const arr = JSON.parse(text);
    if (!Array.isArray(arr)) {
      return res.status(400).json({ error: 'Invalid concat JSON: root is not an array' });
    }

    const picked = new Map(); // id -> { idKey, idValue, xp, tier }
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const idInfo = getIdFromObject(item, idKey);
      if (!idInfo) continue;
      const id = `${idInfo.key}::${idInfo.value}`;
      const xpInfo = getXpPointsFromObject(item);
      const xp = xpInfo ? xpInfo.value : undefined;
      if (xp === undefined) continue;
      const tierNum = toNumber(item?.tier);
      const prev = picked.get(id);
      if (!prev || xp > prev.xp) picked.set(id, { idKey: idInfo.key, idValue: idInfo.value, xp, tier: (Number.isFinite(tierNum) ? tierNum : undefined) });
    }

    let total_aura = 0; // inclusive of all tiers
    let total_aura_excl_t4 = 0; // excludes Tier 4
    let minXp = Number.POSITIVE_INFINITY;
    let maxXp = 0;
    const tierCounts = new Map(); // tier -> count
    let tieredUsers = 0;
    for (const v of picked.values()) {
      total_aura += v.xp;
      if (v.tier === 4) {
        // exclude tier 4 from this subtotal
      } else {
        total_aura_excl_t4 += v.xp;
      }
      if (v.xp < minXp) minXp = v.xp;
      if (v.xp > maxXp) maxXp = v.xp;
      if (Number.isFinite(v.tier)) {
        tieredUsers++;
        const t = v.tier;
        tierCounts.set(t, (tierCounts.get(t) || 0) + 1);
      }
    }
    const count = picked.size;
    const avgXp = count > 0 ? total_aura / count : 0;

    // Convert tierCounts map to a plain object sorted by tier ascending for readability
    const tier_counts = {};
    const sortedTiers = Array.from(tierCounts.entries()).sort((a, b) => a[0] - b[0]);
    for (const [t, c] of sortedTiers) tier_counts[t] = c;

    return res.json({ ok: true, jsonFile, idKeyUsed: (idKey || (count ? [...picked.values()][0].idKey : null)),
      total_users: count,
      total_aura, // inclusive
      total_aura_excl_tier4: total_aura_excl_t4,
      min_xp: (count ? minXp : 0), max_xp: maxXp, avg_xp: avgXp,
      tier_counts, tiered_users: tieredUsers });
  } catch (err) {
    return res.status(500).json({ error: 'sum-xp failure', message: err?.message || String(err) });
  }
});

// Only start the server when running locally; Vercel will import and handle the app
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Local API listening on http://localhost:${PORT}`);
  });
}

export default app;

// GET /supabase/import-from-files
// Local dosyalardan (concat.json, profile-xp.json, profile-activity.json) Supabase tablolarına veri aktarır.
// Query: concatFile, xpFile, activityFile, chunkSize (default 500)
app.get('/supabase/import-from-files', limiter(RATE_LIMITS.write), async (req, res) => {
  try {
    const concatFile = req.query.concatFile ? String(req.query.concatFile) : path.join(process.cwd(), 'output', 'concat.json');
    const xpFile = req.query.xpFile ? String(req.query.xpFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const chunkSize = Math.max(50, Math.min(1000, Number(req.query.chunkSize ?? 500) || 500));

    async function readJsonSafe(file) {
      try {
        const txt = await fs.readFile(file, 'utf8');
        return JSON.parse(txt);
      } catch {
        return undefined;
      }
    }

    function chunk(arr, size) {
      const out = [];
      for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
      return out;
    }

  const keyPref = String(req.query.key || '').toLowerCase();
  const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
  const adminToken = req.headers['x-admin-token'] || req.headers['x-admin'] || '';
  let keyMode = 'anon';
  if (keyPref === 'service' || (keyPref !== 'anon' && hasService)) {
    if (!hasService) return res.status(400).json({ error: 'Service key not configured', message: 'Set SUPABASE_SERVICE_ROLE_KEY or use key=anon' });
    if (!process.env.ADMIN_TOKEN || adminToken !== process.env.ADMIN_TOKEN) {
      return res.status(403).json({ error: 'Forbidden', message: 'Admin token required for service key operations.' });
    }
    keyMode = 'service';
  }
  const sb = getSupabase(keyMode);

    // USERS
    const concatArr = await readJsonSafe(concatFile);
    if (!Array.isArray(concatArr)) return res.status(400).json({ error: 'Invalid concat JSON', concatFile });
    const seen = new Set();
    const usersRows = [];
    for (const item of concatArr) {
      if (!item || typeof item !== 'object') continue;
      const id = Number(item.user_id ?? item.userId ?? item.id);
      if (!Number.isFinite(id) || id <= 0) continue;
      if (seen.has(id)) continue;
      seen.add(id);
      const username = String(item.user_name ?? item.username ?? item.handle ?? '') || `user-${id}`;
      const avatar_url = String(item.avatar_url ?? item.avatar ?? '') || null;
      usersRows.push({ id, username, avatar_url });
    }

    let usersInserted = 0;
    for (const batch of chunk(usersRows, chunkSize)) {
      const { error, count } = await sb.from('users').upsert(batch, { onConflict: 'id', ignoreDuplicates: false, count: 'exact' });
      if (error) return res.status(500).json({ error: 'Supabase users upsert failed', message: error.message });
      usersInserted += (count ?? batch.length);
    }

    // XP
    const xpData = await readJsonSafe(xpFile);
    const xpResults = Array.isArray(xpData?.results) ? xpData.results : [];
    const xpRows = [];
    for (const r of xpResults) {
      if (!r || typeof r !== 'object') continue;
      const user_id = Number(r.userId ?? r.userid ?? r.id);
      if (!Number.isFinite(user_id)) continue;
      const xp_points = (typeof r.xp_points === 'number') ? r.xp_points : (r.xp_points == null ? null : Number(r.xp_points));
      const ok = r.ok === undefined ? null : Boolean(r.ok);
      const status = r.status === undefined ? null : Number(r.status);
      xpRows.push({ user_id, xp_points, ok, status });
    }
    let xpUpserts = 0;
    for (const batch of chunk(xpRows, chunkSize)) {
      const { error, count } = await sb.from('user_xp').upsert(batch, { onConflict: 'user_id', ignoreDuplicates: false, count: 'exact' });
      if (error) return res.status(500).json({ error: 'Supabase user_xp upsert failed', message: error.message });
      xpUpserts += (count ?? batch.length);
    }

    // ACTIVITY
    const actData = await readJsonSafe(activityFile);
    const actResults = Array.isArray(actData?.results) ? actData.results : [];
    const actRows = [];
    for (const r of actResults) {
      if (!r || typeof r !== 'object') continue;
      const user_id = Number(r.userId ?? r.userid ?? r.id);
      if (!Number.isFinite(user_id)) continue;
      const addresses = Number(r.addresses) || 0;
      const threads = Number(r.threads) || 0;
      const comments = Number(r.comments) || 0;
      const total_upvotes = Number(r.totalUpvotes) || 0;
      const comment_threads = Number(r.commentThreads) || 0;
      actRows.push({ user_id, addresses, threads, comments, total_upvotes, comment_threads });
    }
    let actUpserts = 0;
    for (const batch of chunk(actRows, chunkSize)) {
      const { error, count } = await sb.from('user_activity').upsert(batch, { onConflict: 'user_id', ignoreDuplicates: false, count: 'exact' });
      if (error) return res.status(500).json({ error: 'Supabase user_activity upsert failed', message: error.message });
      actUpserts += (count ?? batch.length);
    }

  return res.json({ ok: true, keyMode, usersInserted, xpUpserts, actUpserts, concatFile, xpFile, activityFile });
  } catch (err) {
    return res.status(500).json({ error: 'Import from files failed', message: err?.message || String(err) });
  }
});

// GET /supabase/import-from-xp-activity
// Tek bir birleşik JSON'dan (profile-xp-activity.json) verileri Supabase'e aktarır.
// Query: file, chunkSize (default 500)
app.get('/supabase/import-from-xp-activity', limiter(RATE_LIMITS.write), async (req, res) => {
  try {
    const file = req.query.file ? String(req.query.file) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const chunkSize = Math.max(50, Math.min(1000, Number(req.query.chunkSize ?? 500) || 500));
    const safe = String(req.query.safe ?? req.query.compat ?? 'false').toLowerCase() === 'true';

    async function readJsonSafe(file) {
      try { const txt = await fs.readFile(file, 'utf8'); return JSON.parse(txt); } catch { return undefined; }
    }
    function chunk(arr, size) { const out = []; for (let i=0;i<arr.length;i+=size) out.push(arr.slice(i,i+size)); return out; }

    const data = await readJsonSafe(file);
    const rows = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : [];
    if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'Invalid or empty JSON', file });

    const keyPref = String(req.query.key || '').toLowerCase();
    const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
    const adminToken = req.headers['x-admin-token'] || req.headers['x-admin'] || '';
    let keyMode = 'anon';
    if (keyPref === 'service' || (keyPref !== 'anon' && hasService)) {
      if (!hasService) return res.status(400).json({ error: 'Service key not configured', message: 'Set SUPABASE_SERVICE_ROLE_KEY or use key=anon' });
      if (!process.env.ADMIN_TOKEN || adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(403).json({ error: 'Forbidden', message: 'Admin token required for service key operations.' });
      }
      keyMode = 'service';
    }
    const sb = getSupabase(keyMode);

    // Prepare rows for each table
    const usersRows = [];
    const xpRows = [];
    const actRows = [];

    const seenUsers = new Set();
    for (const r of rows) {
      if (!r || typeof r !== 'object') continue;
      const id = Number(r.userId ?? r.userid ?? r.id);
      if (!Number.isFinite(id) || id <= 0) continue;
      if (!seenUsers.has(id)) {
        seenUsers.add(id);
        const display_name = r?.profile?.name ? String(r.profile.name) : null;
        const avatar_url = r?.profile?.avatar_url ? String(r.profile.avatar_url) : null;
        // username bilinmiyorsa dokunma; yalnızca varsa set edelim
        const urow = { id };
        if (!safe && display_name) urow.display_name = display_name;
        if (avatar_url) urow.avatar_url = avatar_url;
        usersRows.push(urow);
      }
      // xp
      const xp_points = r?.xp_points == null ? null : Number(r.xp_points);
      if (xp_points !== null && Number.isFinite(xp_points)) {
        xpRows.push({ user_id: id, xp_points });
      }
      // activity
      const addresses = Number(r.addresses) || 0;
      const threads = Number(r.threads) || 0;
      const comments = Number(r.comments) || 0;
      const total_upvotes = Number(r.totalUpvotes) || 0;
      const comment_threads = Number(r.commentThreads) || 0;
      const referred_by_address = r.referred_by_address ? String(r.referred_by_address) : null;
      const arow = { user_id: id, addresses, threads, comments, total_upvotes, comment_threads };
      if (!safe && referred_by_address) arow.referred_by_address = referred_by_address;
      actRows.push(arow);
    }

    // Upserts
    let usersUpserts = 0;
    if (usersRows.length) {
      for (const batch of chunk(usersRows, chunkSize)) {
        const { error, count } = await sb.from('users').upsert(batch, { onConflict: 'id', ignoreDuplicates: false, count: 'exact' });
        if (error) return res.status(500).json({ error: 'Supabase users upsert failed', message: error.message });
        usersUpserts += (count ?? batch.length);
      }
    }

    let xpUpserts = 0;
    if (xpRows.length) {
      for (const batch of chunk(xpRows, chunkSize)) {
        const { error, count } = await sb.from('user_xp').upsert(batch, { onConflict: 'user_id', ignoreDuplicates: false, count: 'exact' });
        if (error) return res.status(500).json({ error: 'Supabase user_xp upsert failed', message: error.message });
        xpUpserts += (count ?? batch.length);
      }
    }

    let actUpserts = 0;
    if (actRows.length) {
      for (const batch of chunk(actRows, chunkSize)) {
        const { error, count } = await sb.from('user_activity').upsert(batch, { onConflict: 'user_id', ignoreDuplicates: false, count: 'exact' });
        if (error) return res.status(500).json({ error: 'Supabase user_activity upsert failed', message: error.message });
        actUpserts += (count ?? batch.length);
      }
    }

    return res.json({ ok: true, file, usersUpserts, xpUpserts, actUpserts, keyMode });
  } catch (err) {
    return res.status(500).json({ error: 'Import from xp-activity failed', message: err?.message || String(err) });
  }
});

// GET /supabase/import-user-profile-stats
// profile-activity.json'dan user_profile_stats tablosuna upsert eder.
// Query: file, chunkSize (default 500)
app.get('/supabase/import-user-profile-stats', limiter(RATE_LIMITS.write), async (req, res) => {
  try {
    const file = req.query.file ? String(req.query.file) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const chunkSize = Math.max(50, Math.min(1000, Number(req.query.chunkSize ?? 500) || 500));

    async function readJsonSafe(file) {
      try { const txt = await fs.readFile(file, 'utf8'); return JSON.parse(txt); } catch { return undefined; }
    }
    function chunk(arr, size) { const out = []; for (let i=0;i<arr.length;i+=size) out.push(arr.slice(i,i+size)); return out; }

    const data = await readJsonSafe(file);
    const rows = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : [];
    if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'Invalid or empty JSON', file });

    const keyPref = String(req.query.key || '').toLowerCase();
    const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
    let keyMode = 'anon';
    if (keyPref === 'service') {
      if (!hasService) return res.status(400).json({ error: 'Service key not configured', message: 'Set SUPABASE_SERVICE_ROLE_KEY or use key=anon' });
      keyMode = 'service';
    } else if (keyPref === 'anon') {
      keyMode = 'anon';
    } else {
      keyMode = hasService ? 'service' : 'anon';
    }
    const sb = getSupabase(keyMode);
    // Preflight: table existence check
    try {
      const { error: tErr } = await sb.from('user_profile_stats').select('user_id').limit(1);
      // If table doesn't exist, PostgREST returns a 42P01 error; report friendly message
      if (tErr && /relation .* does not exist|42P01/i.test(tErr.message || '')) {
        return res.status(400).json({ error: 'Missing table user_profile_stats', message: 'Run SQL migration to create user_profile_stats before importing.' });
      }
    } catch {}

    // Build stats rows
    const statsRows = [];
    const seen = new Set();
    for (const r of rows) {
      if (!r || typeof r !== 'object') continue;
      const user_id = Number(r.userId ?? r.userid ?? r.id);
      if (!Number.isFinite(user_id) || user_id <= 0) continue;
      if (seen.has(user_id)) continue;
      seen.add(user_id);
      const display_name = r?.profile?.name ? String(r.profile.name) : null;
      const avatar_url = r?.profile?.avatar_url ? String(r.profile.avatar_url) : null;
      const xp_points = r?.xp_points == null ? null : Number(r.xp_points);
      const addresses = Number(r.addresses) || 0;
      const threads = Number(r.threads) || 0;
      const comments = Number(r.comments) || 0;
      const total_upvotes = Number(r.totalUpvotes) || 0;
      const comment_threads = Number(r.commentThreads) || 0;
      const referred_by_address = r?.referred_by_address ? String(r.referred_by_address) : null;
      statsRows.push({ user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, referred_by_address });
    }

    // Upsert into user_profile_stats
    let upserts = 0;
    for (const batch of chunk(statsRows, chunkSize)) {
      const { error, count } = await sb.from('user_profile_stats').upsert(batch, { onConflict: 'user_id', ignoreDuplicates: false, count: 'exact' });
      if (error) return res.status(500).json({ error: 'Supabase user_profile_stats upsert failed', message: error.message });
      upserts += (count ?? batch.length);
    }

    return res.json({ ok: true, file, upserts, keyMode });
  } catch (err) {
    return res.status(500).json({ error: 'Import user_profile_stats failed', message: err?.message || String(err) });
  }
});

// GET /supabase/import-user-profile-stats-lamumu
// profile_stats_lamumu.json'dan user_profile_stats tablosuna upsert eder (varsa update, yoksa insert).
// Query: file (default output/profile_stats_lamumu.json), chunkSize (default 500), key=service|anon
app.get('/supabase/import-user-profile-stats-lamumu', limiter(RATE_LIMITS.write), async (req, res) => {
  if (!requireAdminInProd(req, res)) return;
  try {
    const file = req.query.file ? String(req.query.file) : path.join(process.cwd(), 'output', 'profile_stats_lamumu.json');
    const chunkSize = Math.max(50, Math.min(1000, Number(req.query.chunkSize ?? 500) || 500));
    const insertOnly = String(req.query.insertOnly ?? 'false').toLowerCase() === 'true'; // if true, ON CONFLICT DO NOTHING (no UPDATE)
    const ensureUsers = String(req.query.ensureUsers ?? 'true').toLowerCase() !== 'false'; // insert minimal users before stats upsert

    async function readJsonSafe(file) {
      try { const txt = await fs.readFile(file, 'utf8'); return JSON.parse(txt); } catch { return undefined; }
    }
    function chunk(arr, size) { const out = []; for (let i=0;i<arr.length;i+=size) out.push(arr.slice(i,i+size)); return out; }

    const data = await readJsonSafe(file);
    const rows = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : [];
    if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'Invalid or empty JSON', file });

    // Key mode selection
    const keyPref = String(req.query.key || '').toLowerCase();
    const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
    let keyMode = 'anon';
    if (keyPref === 'service') {
      if (!hasService) return res.status(400).json({ error: 'Service key not configured', message: 'Set SUPABASE_SERVICE_ROLE_KEY or use key=anon' });
      keyMode = 'service';
    } else if (keyPref === 'anon') {
      keyMode = 'anon';
    } else {
      keyMode = hasService ? 'service' : 'anon';
    }
    const sb = getSupabase(keyMode);

    // Preflight: table and optional column (lamumu_count) existence check
    let hasLamumu = true;
    try {
      const { error: tErr } = await sb.from('user_profile_stats').select('user_id').limit(1);
      if (tErr && /relation .* does not exist|42P01/i.test(tErr.message || '')) {
        return res.status(400).json({ error: 'Missing table user_profile_stats', message: 'Create user_profile_stats before importing.' });
      }
      const { error: cErr } = await sb.from('user_profile_stats').select('user_id, lamumu_count').limit(1);
      if (cErr && /column .* does not exist|42703/i.test(cErr.message || '')) {
        hasLamumu = false;
      }
    } catch {}

    // Detect available columns in users table to avoid schema cache errors
    let usersCols = { username: true, display_name: true, avatar_url: true };
    try {
      const { error: uErr } = await sb.from('users').select('id, username, avatar_url, display_name').limit(1);
      if (uErr) {
        const msg = String(uErr.message || '');
        if (/display_name/i.test(msg)) usersCols.display_name = false;
        if (/username/i.test(msg)) usersCols.username = false;
        if (/avatar_url/i.test(msg)) usersCols.avatar_url = false;
      }
    } catch {}

    // Build upsert rows
    const upRows = [];
    const usersRows = [];
    const seen = new Set();
    for (const r of rows) {
      if (!r || typeof r !== 'object') continue;
      const user_id = Number(r.user_id ?? r.userId ?? r.id);
      if (!Number.isFinite(user_id) || user_id <= 0) continue;
      if (seen.has(user_id)) continue;
      seen.add(user_id);
      const obj = {
        user_id,
        display_name: r.display_name ?? (r.profile && r.profile.name ? String(r.profile.name) : null),
        avatar_url: r.avatar_url ?? (r.profile && r.profile.avatar_url ? String(r.profile.avatar_url) : null),
        xp_points: r.xp_points == null ? null : Number(r.xp_points) || 0,
        addresses: Number(r.addresses) || 0,
        threads: Number(r.threads) || 0,
        comments: Number(r.comments) || 0,
        total_upvotes: Number(r.total_upvotes ?? r.totalUpvotes) || 0,
        comment_threads: Number(r.comment_threads ?? r.commentThreads) || 0,
      };
      if (hasLamumu) obj.lamumu_count = Number(r.lamumu_count) || 0;
      upRows.push(obj);

      // Minimal users row to satisfy FK — include only columns that exist
      const urow = { id: user_id };
      if (usersCols.display_name && obj.display_name != null) urow.display_name = obj.display_name;
      if (usersCols.username && obj.display_name != null) {
        // optionally map display_name to username if username column exists and value not provided elsewhere
        // keep it conservative: do not override if no good source
      }
      if (usersCols.avatar_url && obj.avatar_url != null) urow.avatar_url = obj.avatar_url;
      usersRows.push(urow);
    }
    if (upRows.length === 0) return res.status(400).json({ error: 'No valid rows to upsert', file });

    // Ensure users exist (FK) before upserting stats
    let usersUpserts = 0;
    if (ensureUsers && usersRows.length) {
      for (const batch of chunk(usersRows, chunkSize)) {
        const { error, count } = await sb
          .from('users')
          .upsert(batch, { onConflict: 'id', ignoreDuplicates: insertOnly, count: 'exact' });
        if (error) return res.status(500).json({ error: 'Supabase users upsert failed', message: error.message, keyMode, insertOnly });
        usersUpserts += (count ?? (insertOnly ? 0 : batch.length));
      }
    }

    // Upsert in chunks
    let upserts = 0;
    for (const batch of chunk(upRows, chunkSize)) {
      const { error, count } = await sb
        .from('user_profile_stats')
        .upsert(batch, { onConflict: 'user_id', ignoreDuplicates: insertOnly, count: 'exact' });
      if (error) return res.status(500).json({ error: 'Supabase user_profile_stats upsert failed', message: error.message, keyMode, insertOnly });
      upserts += (count ?? (insertOnly ? 0 : batch.length));
    }

    return res.json({ ok: true, file, upserts, usersUpserts, keyMode, hasLamumu, insertOnly, ensureUsers });
  } catch (err) {
    return res.status(500).json({ error: 'Import user_profile_stats from lamumu failed', message: err?.message || String(err) });
  }
});

// GET /supabase/ping
// Supabase bağlantısını ve env yapılandırmasını doğrular (gizli anahtarları göstermez).
app.get('/supabase/ping', async (req, res) => {
  try {
    if (process.env.NODE_ENV === 'production' || process.env.VERCEL) {
      return res.status(404).json({ error: 'Not found' });
    }
    const forceKey = '';
    const hasUrl = !!process.env.SUPABASE_URL;
    const hasAnon = !!process.env.SUPABASE_ANON_KEY;
    const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
  const keyInUse = hasAnon ? 'anon' : (hasService ? 'service' : null);
    let projectRef = null;
    try {
      if (process.env.SUPABASE_URL) {
        const u = new URL(process.env.SUPABASE_URL);
        // Expect <ref>.supabase.co
        const host = u.hostname;
        projectRef = host?.split('.')?.[0] || null;
      }
    } catch {}

    // Try a light query if possible
    let queryOk = false;
    let queryError = null;
    try {
  const sb = getSupabase();
      const { error } = await sb.from('users').select('id').limit(1);
      if (!error) queryOk = true; else queryError = error.message || String(error);
    } catch (e) {
      queryError = e?.message || String(e);
    }

    // Minimize details on production/Vercel
    if (process.env.NODE_ENV === 'production' || process.env.VERCEL) {
      return res.json({ ok: queryOk });
    }
    return res.json({ ok: queryOk, keyInUse, forced: false, hasUrl, hasAnon, hasService, projectRef, error: queryError });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err?.message || String(err) });
  }
});

// GET /supabase/summary-upsert-from-files
// Reads local JSONs (concat.json, profile-xp.json, profile-activity.json), computes summary metrics,
// and upserts a single row into summary_stats (default id=1) in Supabase.
// Query: concatFile (for total_users), xpFile, activityFile, id (default 1), onlyOk=true|false, threshold (default 1000),
//        key=anon|service, totalUsers (optional override)
app.get('/supabase/summary-upsert-from-files', limiter(RATE_LIMITS.write), async (req, res) => {
  try {
    const concatFile = req.query.concatFile ? String(req.query.concatFile) : path.join(process.cwd(), 'output', 'concat.json');
    const xpFile = req.query.xpFile ? String(req.query.xpFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const activityFile = req.query.activityFile ? String(req.query.activityFile) : path.join(process.cwd(), 'output', 'profile-activity.json');
    const rowId = Number(req.query.id ?? 1) || 1;
    const onlyOk = String(req.query.onlyOk ?? 'true').toLowerCase() !== 'false';
    const threshold = Number(req.query.threshold ?? 1000) || 1000;
    const totalUsersOverride = req.query.totalUsers !== undefined ? Number(req.query.totalUsers) : undefined;

    async function readJsonSafe(file) {
      try {
        const txt = await fs.readFile(file, 'utf8');
        return JSON.parse(txt);
      } catch { return undefined; }
    }

    const [concatArr, xpData, actData] = await Promise.all([
      readJsonSafe(concatFile),
      readJsonSafe(xpFile),
      readJsonSafe(activityFile),
    ]);

    // total_users: prefer explicit override; else dedupe users in concat array; else fall back to xp results count
    let total_users = Number.isFinite(totalUsersOverride) ? totalUsersOverride : undefined;
    if (total_users === undefined && Array.isArray(concatArr)) {
      const seen = new Set();
      for (const item of concatArr) {
        if (!item || typeof item !== 'object') continue;
        const id = Number(item.user_id ?? item.userId ?? item.id);
        if (!Number.isFinite(id)) continue;
        seen.add(id);
      }
      total_users = seen.size;
    }

    const xpResults = Array.isArray(xpData?.results) ? xpData.results : [];
    let total_aura = 0;
    let max_aura = 0;
    let max_aura_user_id = null;
    let users_over_1000 = 0;
    let zero_aura_count = 0;
    const okIds = new Set();
    for (const r of xpResults) {
      if (!r || typeof r !== 'object') continue;
      if (onlyOk && r.ok === false) continue;
      const uid = Number(r.userId ?? r.userid ?? r.id);
      const n = toNumber(r.xp_points);
      if (!Number.isFinite(uid) || n === undefined) continue;
      okIds.add(uid);
      total_aura += n;
      if (n > max_aura) { max_aura = n; max_aura_user_id = uid; }
      if (n > threshold) users_over_1000++;
      if (n === 0) zero_aura_count++;
    }
    if (total_users === undefined) total_users = okIds.size;

    const actResults = Array.isArray(actData?.results) ? actData.results : [];
    let total_addresses = 0, total_threads = 0, total_comments = 0, total_upvotes = 0, total_comment_threads = 0;
    for (const r of actResults) {
      if (!r || typeof r !== 'object') continue;
      const uid = Number(r.userId ?? r.userid ?? r.id);
      if (!Number.isFinite(uid)) continue;
      if (onlyOk && !okIds.has(uid)) continue;
      total_addresses += toNumber(r.addresses) || 0;
      total_threads += toNumber(r.threads) || 0;
      total_comments += toNumber(r.comments) || 0;
      total_upvotes += toNumber(r.totalUpvotes) || 0;
      total_comment_threads += toNumber(r.commentThreads) || 0;
    }

    // Key selection: anon by default; service allowed only with ADMIN_TOKEN
    const keyPref = String(req.query.key || '').toLowerCase();
    const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
    const adminToken = req.headers['x-admin-token'] || req.headers['x-admin'] || '';
    let keyMode = 'anon';
    if (keyPref === 'service') {
      if (!hasService) return res.status(400).json({ error: 'Service key not configured', message: 'Set SUPABASE_SERVICE_ROLE_KEY or use key=anon' });
      if (!process.env.ADMIN_TOKEN || adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(403).json({ error: 'Forbidden', message: 'Admin token required for service key operations.' });
      }
      keyMode = 'service';
    }
    const sb = getSupabase(keyMode);
    // Check if zero_aura_count column exists; include conditionally
    let hasZeroAura = true;
    try {
      const { error: cErr } = await sb.from('summary_stats').select('zero_aura_count').limit(1);
      if (cErr && /column .* does not exist|42703/i.test(cErr.message || '')) hasZeroAura = false;
    } catch { hasZeroAura = false; }

    const payload = {
      id: rowId,
      total_users,
      total_aura,
      max_aura,
      max_aura_user_id,
      users_over_1000,
      total_addresses,
      total_threads,
      total_comments,
      total_upvotes,
      total_comment_threads,
      ...(hasZeroAura ? { zero_aura_count } : {}),
    };
    const { error } = await sb.from('summary_stats').upsert([payload], { onConflict: 'id', ignoreDuplicates: false });
    if (error) return res.status(500).json({ error: 'Supabase summary_stats upsert failed', message: error.message, payload });

    return res.json({ ok: true, keyMode, payload });
  } catch (err) {
    return res.status(500).json({ error: 'Summary upsert from files failed', message: err?.message || String(err) });
  }
});

// GET /supabase/summary-upsert-from-stats
// Aggregates metrics directly from user_profile_stats and upserts into summary_stats (default id=1).
// Query: id (default 1), threshold (default 1000), key=anon|service
app.get('/supabase/summary-upsert-from-stats', limiter(RATE_LIMITS.write), async (req, res) => {
  try {
    const rowId = Number(req.query.id ?? 1) || 1;
    const threshold = Number(req.query.threshold ?? 1000) || 1000;
  // PostgREST genelde tek istekte max ~1000 satır döndürür; bu nedenle güvenli varsayılan 1000.
  const pageSize = Math.max(1, Math.min(1000, Number(req.query.pageSize ?? 1000) || 1000));

    // Key selection (anon by default, service if available or explicitly requested)
    const keyPref = String(req.query.key || '').toLowerCase();
    const hasService = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
    const adminToken = req.headers['x-admin-token'] || req.headers['x-admin'] || '';
    // Default to anon unless explicitly requested as service with ADMIN_TOKEN
    let keyMode = 'anon';
    if (keyPref === 'service') {
      if (!hasService) return res.status(400).json({ error: 'Service key not configured', message: 'Set SUPABASE_SERVICE_ROLE_KEY or use key=anon' });
      if (!process.env.ADMIN_TOKEN || adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(403).json({ error: 'Forbidden', message: 'Admin token required for service key operations.' });
      }
      keyMode = 'service';
    }
    const sb = getSupabase(keyMode);

    // Scan table in pages and compute aggregates client-side (avoids PostgREST aggregate restrictions)
  let total_users = 0;
  let sum_xp_points = 0;
  let max_xp_points = 0;
  let max_aura_user_id = null;
  let total_addresses = 0;
  let total_threads = 0;
  let total_comments = 0;
  let total_upvotes = 0;
  let total_comment_threads = 0;
  let users_over_1000 = 0;
  let zero_aura_count = 0;

    let from = 0;
    for (;;) {
      const to = from + pageSize - 1;
      const { data, error } = await sb
        .from('user_profile_stats')
        .select('user_id, xp_points, addresses, threads, comments, total_upvotes, comment_threads')
        .order('user_id', { ascending: true, nullsFirst: false })
        .range(from, to);
      if (error) return res.status(500).json({ error: 'scan failed', message: error.message });
      const rows = Array.isArray(data) ? data : [];
      if (!rows.length) break;
      for (const r of rows) {
        total_users += 1;
        const uid = Number(r.user_id);
        const xp = r.xp_points == null ? 0 : Number(r.xp_points);
        const addr = Number(r.addresses) || 0;
        const thr = Number(r.threads) || 0;
        const com = Number(r.comments) || 0;
        const upv = Number(r.total_upvotes) || 0;
        const cthr = Number(r.comment_threads) || 0;
        sum_xp_points += xp;
        total_addresses += addr;
        total_threads += thr;
        total_comments += com;
        total_upvotes += upv;
        total_comment_threads += cthr;
        if (xp >= threshold) users_over_1000 += 1;
        if (xp === 0) zero_aura_count += 1;
        if (xp > max_xp_points) { max_xp_points = xp; max_aura_user_id = uid; }
      }
      from += rows.length;
      // rows.length < pageSize ise son sayfadayız; yoksa devam et
      if (rows.length < pageSize) break;
    }

    // Upsert summary row
    // Optional column check for zero_aura_count
    let hasZeroAura = true;
    try {
      const { error: cErr } = await sb.from('summary_stats').select('zero_aura_count').limit(1);
      if (cErr && /column .* does not exist|42703/i.test(cErr.message || '')) hasZeroAura = false;
    } catch { hasZeroAura = false; }

    const payload = {
      id: rowId,
      total_users,
      total_aura: sum_xp_points,
      max_aura: max_xp_points,
      max_aura_user_id,
      users_over_1000,
      total_addresses,
      total_threads,
      total_comments,
      total_upvotes,
      total_comment_threads,
      ...(hasZeroAura ? { zero_aura_count } : {}),
      updated_at: new Date().toISOString(),
    };
    const { error: upErr } = await sb.from('summary_stats').upsert(payload, { onConflict: 'id' });
    if (upErr) return res.status(500).json({ error: 'summary upsert failed', message: upErr.message });

    return res.json({ ok: true, id: rowId, keyMode, summary: payload });
  } catch (err) {
    return res.status(500).json({ error: 'summary from stats failed', message: err?.message || String(err) });
  }
});
