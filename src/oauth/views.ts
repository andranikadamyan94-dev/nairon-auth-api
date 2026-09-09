import { WorkspaceChoice } from './oauth.service';

/**
 * The two screens a person sees while connecting ChatGPT to Nairon.
 *
 * Server-rendered, no scripts, no external assets. That is not minimalism for
 * its own sake: this page takes a password, so the fewer moving parts between
 * the form and the handler, the smaller the surface. Everything interpolated
 * is escaped, including values that came back from the client's own request.
 */

function escape(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLE = `
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#f5f6f8; color:#1c1c1e;
         font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; padding:24px; }
  .card { width:100%; max-width:400px; background:#fff; border:1px solid #e3e5e8; border-radius:14px;
          padding:28px; box-shadow:0 1px 3px rgba(0,0,0,.06); }
  h1 { margin:0 0 4px; font-size:19px; font-weight:650; }
  .sub { margin:0 0 22px; color:#6b7280; font-size:13.5px; }
  label { display:block; margin:0 0 6px; font-size:13px; font-weight:600; color:#374151; }
  input[type=email], input[type=password] { width:100%; padding:10px 12px; margin-bottom:16px;
          border:1px solid #d6d9de; border-radius:9px; font-size:15px; background:#fff; color:inherit; }
  input:focus { outline:2px solid #2563eb; outline-offset:-1px; border-color:#2563eb; }
  button { width:100%; padding:11px; border:0; border-radius:9px; background:#111827; color:#fff;
           font-size:15px; font-weight:600; cursor:pointer; }
  button:hover { background:#374151; }
  .error { margin:0 0 16px; padding:10px 12px; border-radius:9px; background:#fef2f2;
           border:1px solid #fecaca; color:#991b1b; font-size:13.5px; }
  .scopes { margin:0 0 20px; padding:12px 14px; background:#f9fafb; border:1px solid #eceef1;
            border-radius:9px; font-size:13.5px; color:#4b5563; }
  .scopes ul { margin:8px 0 0; padding-left:18px; }
  .ws { display:flex; gap:10px; align-items:center; padding:11px 12px; margin-bottom:8px;
        border:1px solid #d6d9de; border-radius:9px; cursor:pointer; }
  .ws:hover { border-color:#2563eb; background:#f8faff; }
  .ws input { margin:0; }
  .foot { margin:18px 0 0; font-size:12px; color:#9ca3af; text-align:center; }
  @media (prefers-color-scheme: dark) {
    body { background:#0f1115; color:#e5e7eb; }
    .card { background:#171a21; border-color:#282c35; box-shadow:none; }
    label { color:#cbd5e1; }
    input[type=email], input[type=password] { background:#0f1115; border-color:#333845; color:#e5e7eb; }
    button { background:#2563eb; } button:hover { background:#1d4ed8; }
    .scopes { background:#0f1115; border-color:#282c35; color:#9ca3af; }
    .ws { border-color:#333845; } .ws:hover { background:#111827; }
    .error { background:#2a1416; border-color:#5b1d21; color:#fca5a5; }
  }
`;

function page(title: string, inner: string): string {
  return `<!doctype html><html lang="hy"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escape(title)}</title><style>${STYLE}</style></head>
<body><div class="card">${inner}</div></body></html>`;
}

function scopeList(scope: string): string {
  const lines = scope
    .split(/\s+/)
    .filter(Boolean)
    .map((s) =>
      s === 'offline_access'
        ? '<li>Մնալ միացված (թարմացնող թոկեն)</li>'
        : '<li>Կարդալ Nairon-ի տվյալները ձեր իրավունքների սահմաններում</li>',
    )
    .join('');
  return `<div class="scopes">ChatGPT-ը կխնդրի՝<ul>${lines}</ul></div>`;
}

export function loginPage(input: {
  sealed: string;
  clientName: string;
  scope: string;
  error?: string;
  email?: string;
}): string {
  return page(
    'Nairon — մուտք',
    `<h1>Միացնել ${escape(input.clientName)}</h1>
     <p class="sub">Մուտք գործեք Nairon-ի ձեր հաշվով</p>
     ${input.error ? `<p class="error">${escape(input.error)}</p>` : ''}
     ${scopeList(input.scope)}
     <form method="post" action="/oauth/authorize">
       <input type="hidden" name="request" value="${escape(input.sealed)}">
       <label for="email">Էլ. փոստ</label>
       <input id="email" name="email" type="email" required autocomplete="username"
              value="${escape(input.email ?? '')}" autofocus>
       <label for="password">Գաղտնաբառ</label>
       <input id="password" name="password" type="password" required autocomplete="current-password">
       <button type="submit">Շարունակել</button>
     </form>
     <p class="foot">Ձեր գաղտնաբառը ChatGPT-ին չի փոխանցվում</p>`,
  );
}

export function workspacePage(input: {
  sealed: string;
  clientName: string;
  scope: string;
  workspaces: WorkspaceChoice[];
  error?: string;
}): string {
  const options = input.workspaces
    .map(
      (w, i) =>
        `<label class="ws"><input type="radio" name="entityId" value="${escape(w.id)}"${
          i === 0 ? ' checked' : ''
        }><span>${escape(w.name)}</span></label>`,
    )
    .join('');
  return page(
    'Nairon — ընտրել աշխատատարածքը',
    `<h1>Ընտրեք աշխատատարածքը</h1>
     <p class="sub">${escape(input.clientName)} կաշխատի միայն այս աշխատատարածքում</p>
     ${input.error ? `<p class="error">${escape(input.error)}</p>` : ''}
     <form method="post" action="/oauth/authorize">
       <input type="hidden" name="request" value="${escape(input.sealed)}">
       <input type="hidden" name="consent" value="1">
       ${options}
       <button type="submit" style="margin-top:12px">Թույլատրել</button>
     </form>
     <p class="foot">Փոխելու համար անհրաժեշտ կլինի կրկին միանալ</p>`,
  );
}

export function errorPage(message: string): string {
  return page(
    'Nairon — սխալ',
    `<h1>Հնարավոր չէ շարունակել</h1><p class="error">${escape(message)}</p>
     <p class="foot">Փակեք այս էջը և կրկին փորձեք ChatGPT-ից</p>`,
  );
}
