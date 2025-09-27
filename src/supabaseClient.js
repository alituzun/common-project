import { createClient } from '@supabase/supabase-js';

// Initialize Supabase client from environment variables.
// Required:
// - SUPABASE_URL
// - SUPABASE_ANON_KEY (for public or RLS-enabled reads)
// Optional (for server-side service role access — be careful!):
// - SUPABASE_SERVICE_ROLE_KEY
//
// Note:
// - Prefer using ANON key with Row Level Security (RLS) policies for read-only endpoints.
// - If you must use SERVICE_ROLE, NEVER expose it to the browser; keep it server-side only.

let cachedDefault = null;
let cachedAnon = null;
let cachedService = null;

export function getSupabase(mode) {
  // Desteklenen env isimleri (fallback sırayla):
  // URL: SUPABASE_URL -> NEXT_PUBLIC_SUPABASE_URL -> SUPABASE_PROJECT_URL
  // ANON: SUPABASE_ANON_KEY -> NEXT_PUBLIC_SUPABASE_ANON_KEY -> SUPABASE_KEY
  // SERVICE: SUPABASE_SERVICE_ROLE_KEY
  const url = process.env.SUPABASE_URL
    || process.env.NEXT_PUBLIC_SUPABASE_URL
    || process.env.SUPABASE_PROJECT_URL;
  const anon = process.env.SUPABASE_ANON_KEY
    || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    || process.env.SUPABASE_KEY;
  const serviceRole = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !(anon || serviceRole)) {
  throw new Error('Supabase env missing: set SUPABASE_URL (or NEXT_PUBLIC_SUPABASE_URL) and SUPABASE_ANON_KEY (or NEXT_PUBLIC_SUPABASE_ANON_KEY) — or set SUPABASE_SERVICE_ROLE_KEY');
  }

  // Mode belirleme: explicit param > env tercih > default (anon)
  const envPref = (process.env.SUPABASE_PREFERRED_KEY || '').toLowerCase(); // 'anon' | 'service'
  let resolvedMode = mode;
  if (!resolvedMode) resolvedMode = (envPref === 'service') ? 'service' : 'anon';

  // Mevcut cache varsa kullan
  if (resolvedMode === 'service' && cachedService) return cachedService;
  if (resolvedMode === 'anon' && cachedAnon) return cachedAnon;
  if (!mode && cachedDefault) return cachedDefault;

  const key = resolvedMode === 'service' ? serviceRole : anon;
  const client = createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
    global: {
      headers: {
        'X-Client-Info': 'common-local-api/1.0.0',
      },
    },
  });
  if (resolvedMode === 'service') {
    cachedService = client;
  } else if (resolvedMode === 'anon') {
    cachedAnon = client;
  } else {
    cachedDefault = client;
  }
  return client;
}
