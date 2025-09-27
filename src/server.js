import express from 'express';
import { promises as fs } from 'fs';
import fsSync from 'fs';
import path from 'path';
import { setTimeout as wait } from 'timers/promises';
import 'dotenv/config';
import { getSupabase } from './supabaseClient.js';

const app = express();
const PORT = process.env.PORT || 3001;

// Basic CORS (adjust as needed). Allows common headers and credentials if needed.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Admin-Token, X-Admin');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (_req, res) => res.json({ ok: true }));

// Helper: sanitize and prepare headers for upstream call
function buildUpstreamHeaders(reqHeaders) {
  const drop = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade', 'via']);
  const h = {};
  for (const [k, v] of Object.entries(reqHeaders || {})) {
    const key = String(k).toLowerCase();
    if (!drop.has(key) && v !== undefined && v !== null) h[key] = v;
  }
  // Provide some sensible defaults if caller didn't set them
  h['accept'] ||= 'application/json, text/plain, */*';
  h['accept-encoding'] ||= 'gzip, deflate, br, zstd';
  h['accept-language'] ||= 'en-US,en;q=0.8';
  h['user-agent'] ||= 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';
  h['origin'] ||= 'https://common.xyz';
  h['referer'] ||= 'https://common.xyz/leaderboard';
  return h;
}

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

    const limit = Number(req.query.limit ?? 50) || 50;
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

    const start = Number(req.query.start ?? 1) || 1;
    const limit = Number(req.query.limit ?? 50) || 50;
    const direction = String(req.query.direction ?? 'forward');
    const max = Math.min(Number(req.query.max ?? 1000) || 1000, 10000); // hard cap
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
              continue; // drop it
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

// GET /xps-ranked/profile-xp-runall
// Processes ALL IDs from concat.json with dynamic throttling and periodic writes.
// Auto-resumes from existing output/profile-xp.json; supports mutateSource to shrink concat.json.
// Query: jsonFile, idKey, outFile, concurrency (default 2), targetRps (default 1), flushEvery (default 100),
//        baseDelayMs (default 500), maxRetries (default 6), mutateSource=false|true
app.get('/xps-ranked/profile-xp-runall', async (req, res) => {
  try {
    const { authorization: auth, cookie } = getAuthCookieFromRequest(req);
    if (!auth && !cookie) {
      return res.status(400).json({ error: 'Missing credentials: provide Authorization and/or Cookie (header or query param)' });
    }

    const jsonFile = req.query.jsonFile ? String(req.query.jsonFile) : path.join(process.cwd(), 'output', 'concat.json');
    const idKey = req.query.idKey ? String(req.query.idKey) : 'user_id';
    const outFile = req.query.outFile ? String(req.query.outFile) : path.join(process.cwd(), 'output', 'profile-xp.json');
    const concurrency = Math.max(1, Number(req.query.concurrency ?? 2) || 2);
    const targetRps = Math.max(0.2, Number(req.query.targetRps ?? 1) || 1); // requests per second total
    const flushEvery = Math.max(10, Number(req.query.flushEvery ?? 100) || 100);
    const baseDelayMs = Math.max(100, Number(req.query.baseDelayMs ?? 500) || 500);
    const maxRetries = Math.max(0, Number(req.query.maxRetries ?? 6) || 6);
    const mutateSource = String(req.query.mutateSource ?? 'false').toLowerCase() === 'true';

    const text = await fs.readFile(jsonFile, 'utf8');
    const arr = JSON.parse(text);
    if (!Array.isArray(arr)) return res.status(400).json({ error: 'Invalid JSON: expected top-level array' });

    // Build unique ID list
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

    // Load existing output to resume
    let existing = undefined;
    const doneIds = new Set();
    try {
      const prev = JSON.parse(await fs.readFile(outFile, 'utf8'));
      existing = prev;
      if (Array.isArray(prev?.results)) {
        for (const r of prev.results) {
          if (r && (r.userId !== undefined && r.userId !== null)) doneIds.add(Number(r.userId));
        }
      }
    } catch {}

    const queue = allIds.filter((id) => !doneIds.has(id));
    const headersOut = buildUpstreamHeaders(req.headers);
    if (auth) headersOut['authorization'] = auth;
    if (cookie) headersOut['cookie'] = cookie;

    // Timing control for targetRps
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
      let xp = undefined;
      try {
        const json = JSON.parse(bodyText);
        xp = findMaxXpPoints(json);
      } catch {}
      results.push({ userId, status: resp.status, ok: resp.ok, xp_points: xp ?? null });
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

    // Workers
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

    // Optionally remove processed IDs from concat.json
    let removedFromSource = 0;
    if (mutateSource) {
      try {
        const srcText = await fs.readFile(jsonFile, 'utf8');
        const srcArr = JSON.parse(srcText);
        if (Array.isArray(srcArr)) {
          const doneNow = new Set(results.map((r) => Number(r.userId)));
          const filtered = [];
          for (const item of srcArr) {
            if (!item || typeof item !== 'object') { filtered.push(item); continue; }
            const idInfo = getIdFromObject(item, idKey);
            if (!idInfo) { filtered.push(item); continue; }
            const num = Number(idInfo.value);
            if (!Number.isFinite(num)) { filtered.push(item); continue; }
            if (doneNow.has(num)) { removedFromSource++; continue; }
            filtered.push(item);
          }
          await fs.writeFile(jsonFile, JSON.stringify(filtered, null, 2), 'utf8');
        }
      } catch {}
    }

    return res.json({ ok: true, processed: completed, remaining: queue.length, results: results.length, errors: errors.length, outFile, removedFromSource });
  } catch (err) {
    return res.status(500).json({ error: 'Profile XP runall failure', message: err?.message || String(err) });
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

    // Resume from existing
    let existing = undefined;
    const doneIds = new Set();
    try {
      const prev = JSON.parse(await fs.readFile(outFile, 'utf8'));
      existing = prev;
      const resultsPrev = Array.isArray(prev?.results) ? prev.results : [];
      for (const r of resultsPrev) {
        if (r && (r.userId !== undefined && r.userId !== null)) doneIds.add(Number(r.userId));
      }
    } catch {}

    const queue = allIds.filter((id) => !doneIds.has(id));

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
      try {
        const json = JSON.parse(bodyText);
        activity = computeProfileActivityCounts(json);
        profileMeta = extractProfileInfo(json);
        refer = extractReferralAndXp(json);
      } catch {}
      results.push({ userId, status: resp.status, ok: resp.ok, ...activity, ...(profileMeta || {}), ...(refer || {}) });
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

    return res.json({ ok: true, processed: completed, remaining: queue.length, results: results.length, errors: errors.length, outFile });
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

// Root → summary
app.get('/', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/summary-html' + q);
});

// Canonical routes: Redirect to existing handlers with query preserved
app.get('/summary-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/xps-ranked/summary-html' + q);
});
app.get('/users-html', (req, res) => {
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(308, '/xps-ranked/users-html' + q);
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
    }

  const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : String(n ?? ''));

  const usersCount = summaryRow?.total_users ?? ((act && act.counted) ? act.counted : (xp && xp.counted ? xp.counted : 0));
  const totalAura = summaryRow?.total_aura ?? xp.total;
  const maxAura = summaryRow?.max_aura ?? xp.max;
  const overTh = summaryRow?.users_over_1000 ?? xp.overThreshold;
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
  .topnav{display:flex; gap:10px; align-items:center; justify-content:center}
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
  <a class="btn current" href="/summary-html">Common Stats</a>
    <span class="sep">•</span>
  <a class="btn" href="/users-html">Users stats»</a>
  </div>
  <div class="meta">Data as of 27.09.2025</div>
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
      let qStats = sb
        .from('user_profile_stats')
        .select('user_id, display_name, avatar_url, xp_points, addresses, threads, comments, total_upvotes, comment_threads, users!left(id, username, avatar_url)', { count: 'exact' });

      // Search:
      // - q tamamen rakamsa user_id eşitliği
      // - aksi halde display_name veya users.username üzerinde ILIKE
      if (q) {
        const digits = q.replace(/[^0-9]/g, '');
        if (digits && digits.length === q.length) {
          qStats = qStats.eq('user_id', digits);
        } else {
          // or() ile hem display_name hem de users.username üzerinde arama
          const like = `%${q}%`;
          qStats = qStats.or(`display_name.ilike.${like},users.username.ilike.${like}`);
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

      const { data: statsRows, count, error: statsErr } = await qStats;
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
        return { id, name, avatar, xp, addresses, threads, comments, totalUpvotes, commentThreads };
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
        return `/users-html?${params.toString()}`;
      }

      const rowsHtml = users.map((u, idx) => `
      <tr>
        <td class="cell rank">${fmt(fromIdx + idx + 1)}</td>
        <td class="cell id">${fmt(u.id)}</td>
        <td class="cell user">
          <div class="userbox">
            ${u.avatar ? `<img class="avatar" src="${esc(u.avatar)}" alt="${esc(u.name)}" onerror="this.style.display='none'" />` : ''}
            <div class="meta">
              <div class="name">${esc(u.name)}</div>
            </div>
          </div>
        </td>
        <td class="cell xp">${fmt(u.xp)}</td>
        <td class="cell addresses">${fmt(u.addresses)}</td>
        <td class="cell threads">${fmt(u.threads)}</td>
        <td class="cell comments">${fmt(u.comments)}</td>
        <td class="cell upvotes">${fmt(u.totalUpvotes)}</td>
        <td class="cell cthreads">${fmt(u.commentThreads)}</td>
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
    .topnav{display:flex; gap:10px; align-items:center; justify-content:center}
    .topnav .sep{color:var(--muted)}
    .btn{display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--text); text-decoration:none; font-size:13px}
    .btn:hover{border-color:var(--accent); color:var(--accent)}
    .btn.current{pointer-events:none; opacity:0.8}
    .container{padding:14px 16px; max-width:1280px; margin:0 auto}
    .toolbar{display:flex; align-items:center; justify-content:space-between; color:var(--muted); font-size:12px; margin-bottom:10px}
    .pager a{color:var(--accent); text-decoration:none; margin:0 6px}
    table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden}
    thead th{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; padding:10px; text-align:left; background:#0d1526}
    tbody td{padding:10px; border-top:1px solid var(--line)}
    .userbox{display:flex; align-items:center; gap:10px}
    .avatar{width:36px; height:36px; border-radius:50%; object-fit:cover; border:1px solid var(--line); background:#1e293b}
    .name{font-weight:600}
    .sub{color:var(--muted); font-size:11px}
    .cell.xp,.cell.addresses,.cell.threads,.cell.comments,.cell.upvotes,.cell.cthreads{font-variant-numeric:tabular-nums}
    .pager{margin-top:12px; text-align:center}
    @media (max-width:760px){ .sub{display:none} thead{display:none} table,tbody,tr,td{display:block;width:100%} tbody td{border:none; padding:8px 10px} tr{border:1px solid var(--line); border-radius:12px; margin-bottom:10px; background:var(--card)} .cell{display:flex; justify-content:space-between} .cell::before{content:attr(data-label); color:var(--muted)} }
  </style>
  </head>
  <body>
    <header>
      <div class="topnav">
        <a class="btn" href="/summary-html">Common Stats</a>
        <span class="sep">•</span>
        <a class="btn current" href="/users-html">Users stats»</a>
      </div>
      <div class="meta" style="color:#94a3b8; font-size:12px; margin-top:6px">Data as of 27.09.2025</div>
    </header>
    <div class="container">
      <div class="toolbar">
        <div>
          <div>Totals: ${fmt(total)} • Page ${fmt(curPage)} / ${fmt(totalPages)} • Sorted by ${esc(sortBy)} ${esc(effectiveOrder)}${q ? ` • Search: ${esc(q)}` : ''}</div>
          <form method="GET" action="/users-html" style="display:flex; gap:6px; align-items:center; margin-top:6px">
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
      xpResults = Array.isArray(xpData?.results) ? xpData.results : [];
      actResults = Array.isArray(actData?.results) ? actData.results : [];
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
      users.push({ id, username, avatar, xp, ...act });
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
  return `/users-html?${params.toString()}`;
    }

    const rows = slice.map((u, idx) => `
      <tr>
        <td class="cell rank">${fmt(start + idx + 1)}</td>
        <td class="cell id">${fmt(u.id)}</td>
        <td class="cell user">
          <div class="userbox">
            ${u.avatar ? `<img class="avatar" src="${esc(u.avatar)}" alt="${esc(u.username)}" onerror="this.style.display='none'" />` : ''}
            <div class="meta">
              <div class="name">${esc(u.username)}</div>
            </div>
          </div>
        </td>
        <td class="cell xp">${fmt(u.xp)}</td>
        <td class="cell addresses">${fmt(u.addresses)}</td>
        <td class="cell threads">${fmt(u.threads)}</td>
        <td class="cell comments">${fmt(u.comments)}</td>
        <td class="cell upvotes">${fmt(u.totalUpvotes)}</td>
        <td class="cell cthreads">${fmt(u.commentThreads)}</td>
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
    .topnav{display:flex; gap:10px; align-items:center; justify-content:center}
    .topnav .sep{color:var(--muted)}
    .btn{display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--text); text-decoration:none; font-size:13px}
    .btn:hover{border-color:var(--accent); color:var(--accent)}
    .btn.current{pointer-events:none; opacity:0.8}
    .container{padding:14px 16px; max-width:1280px; margin:0 auto}
    .toolbar{display:flex; align-items:center; justify-content:space-between; color:var(--muted); font-size:12px; margin-bottom:10px}
    .pager a{color:var(--accent); text-decoration:none; margin:0 6px}
    table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden}
    thead th{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; padding:10px; text-align:left; background:#0d1526}
    tbody td{padding:10px; border-top:1px solid var(--line)}
    .userbox{display:flex; align-items:center; gap:10px}
    .avatar{width:36px; height:36px; border-radius:50%; object-fit:cover; border:1px solid var(--line); background:#1e293b}
    .name{font-weight:600}
    .sub{color:var(--muted); font-size:11px}
    .cell.xp,.cell.addresses,.cell.threads,.cell.comments,.cell.upvotes,.cell.cthreads{font-variant-numeric:tabular-nums}
    .pager{margin-top:12px; text-align:center}
    @media (max-width:760px){ .sub{display:none} thead{display:none} table,tbody,tr,td{display:block;width:100%} tbody td{border:none; padding:8px 10px} tr{border:1px solid var(--line); border-radius:12px; margin-bottom:10px; background:var(--card)} .cell{display:flex; justify-content:space-between} .cell::before{content:attr(data-label); color:var(--muted)} }
  </style>
  </head>
  <body>
    <header>
      <div class="topnav">
        <a class="btn" href="/summary-html">Common Stats</a>
        <span class="sep">•</span>
        <a class="btn current" href="/users-html">Users stats»</a>
      </div>
      <div class="meta" style="color:#94a3b8; font-size:12px; margin-top:6px">Data as of 27.09.2025</div>
    </header>
    <div class="container">
      <div class="toolbar">
        <div>
          <div>Totals: ${fmt(total)} • Page ${fmt(curPage)} / ${fmt(totalPages)} • Sorted by ${esc(sortBy)} ${esc(order)}${q ? ` • Search: ${esc(q)}` : ''}</div>
          <form method="GET" action="/users-html" style="display:flex; gap:6px; align-items:center; margin-top:6px">
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
    };

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
        if (xp > max_xp_points) { max_xp_points = xp; max_aura_user_id = uid; }
      }
      from += rows.length;
      // rows.length < pageSize ise son sayfadayız; yoksa devam et
      if (rows.length < pageSize) break;
    }

    // Upsert summary row
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
      updated_at: new Date().toISOString(),
    };
    const { error: upErr } = await sb.from('summary_stats').upsert(payload, { onConflict: 'id' });
    if (upErr) return res.status(500).json({ error: 'summary upsert failed', message: upErr.message });

    return res.json({ ok: true, id: rowId, keyMode, summary: payload });
  } catch (err) {
    return res.status(500).json({ error: 'summary from stats failed', message: err?.message || String(err) });
  }
});
