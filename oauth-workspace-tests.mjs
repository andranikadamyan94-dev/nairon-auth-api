/**
 * Does the OAuth consent screen offer the same workspaces Nairon does?
 *
 * The screen used to build its list from role assignments, which is not the
 * model Nairon uses — hr-api resolves workspaces from the org tree and
 * department memberships. This compares the two answers directly, for real
 * people, and requires them to agree exactly.
 *
 * Read-only: it registers a throwaway OAuth client and walks the consent
 * screen, but issues no code and changes no membership.
 */
const AUTH = 'http://localhost:3002';
const HR = 'http://localhost:3001';
const REDIRECT = 'http://localhost:8765/callback';

const PEOPLE = [
  ['andranik.adamyan.dev@gmail.com', 'Andranik'],
  ['margarita.sargsyan@yazaryanholding.am', 'Margarita'],
  ['mshakhanyanellp@gmail.com', 'Misha'],
  ['harutyun.mkrtchyan.dev@gmail.com', 'Harutyun'],
];

const results = [];
const ok = (name, pass, detail = '') =>
  results.push({ name, pass, detail: String(detail).replace(/\s+/g, ' ').slice(0, 150) });

const form = (o) => new URLSearchParams(o).toString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function post(url, init, attempt = 0) {
  const r = await fetch(url, init);
  if (r.status === 429 && attempt < 3) {
    await sleep(31_000);
    return post(url, init, attempt + 1);
  }
  return r;
}

const reg = await (
  await fetch(`${AUTH}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'workspace parity check',
      redirect_uris: [REDIRECT],
      scope: 'nairon:mcp offline_access',
    }),
  })
).json();

/** What Nairon itself offers this person, through the endpoint the UI uses. */
async function naironEntities(email) {
  const login = await (
    await fetch(`${AUTH}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: '123456789' }),
    })
  ).json();
  if (!login.access_token) return null;
  const res = await fetch(`${HR}/api/entities`, {
    headers: { authorization: `Bearer ${login.access_token}` },
  });
  if (!res.ok) return null;
  const rows = await res.json();
  return Array.isArray(rows) ? rows.map((r) => r.id).sort((a, b) => a - b) : null;
}

/** What the consent screen offers the same person. */
async function consentOffers(email) {
  const url =
    `${AUTH}/oauth/authorize?` +
    form({
      response_type: 'code',
      client_id: reg.client_id,
      redirect_uri: REDIRECT,
      scope: 'nairon:mcp',
      state: 's',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    });
  const page = await post(url, {});
  const html = await page.text();
  const sealed = /name="request" value="([^"]+)"/.exec(html)?.[1];
  if (!sealed) return { error: `no login form (HTTP ${page.status})` };

  const res = await post(`${AUTH}/oauth/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ request: sealed, email, password: '123456789' }),
    redirect: 'manual',
  });

  // One workspace skips the picker and redirects straight away.
  if (res.status === 302) {
    return { single: true, ids: null, sealed: null };
  }
  const body = await res.text();
  if (/չկա|no workspace/i.test(body) || res.status === 403) return { ids: [] };
  const ids = [...body.matchAll(/name="entityId" value="(\d+)"/g)]
    .map((m) => Number(m[1]))
    .sort((a, b) => a - b);
  const next = /name="request" value="([^"]+)"/.exec(body)?.[1];
  return { ids, sealed: next };
}

for (const [email, label] of PEOPLE) {
  const nairon = await naironEntities(email);
  const consent = await consentOffers(email);

  if (nairon === null) {
    ok(`${label} · account usable for the comparison`, false, 'login or hr-api call failed');
    continue;
  }

  if (consent.single) {
    ok(`${label} · consent matches Nairon`, nairon.length === 1,
       `Nairon offers ${nairon.join(',') || 'none'}; consent skipped the picker (single workspace)`);
    continue;
  }

  const same =
    consent.ids.length === nairon.length && consent.ids.every((id, i) => id === nairon[i]);
  ok(`${label} · consent offers exactly what Nairon offers`, same,
     `Nairon [${nairon.join(',')}] vs consent [${consent.ids.join(',')}]`);
}

// A workspace the person was not offered must be refused even if the form says so.
{
  const consent = await consentOffers('margarita.sargsyan@yazaryanholding.am');
  const nairon = await naironEntities('margarita.sargsyan@yazaryanholding.am');
  const forged = [1, 2, 3, 4, 5, 6, 7, 99].find((id) => !(nairon ?? []).includes(id));

  if (consent.sealed && forged !== undefined) {
    const res = await post(`${AUTH}/oauth/authorize`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form({ request: consent.sealed, consent: '1', entityId: String(forged) }),
      redirect: 'manual',
    });
    ok('forged entityId in the consent form is refused', res.status !== 302,
       `entity ${forged} → HTTP ${res.status}`);
  } else {
    ok('forged entityId in the consent form is refused', true,
       'no picker shown for this account — nothing to forge');
  }
}

for (const r of results) {
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `  — ${r.detail}` : ''}`);
}
console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed`);
process.exit(results.every((r) => r.pass) ? 0 : 1);
