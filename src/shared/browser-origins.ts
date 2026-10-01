/**
 * The browser origins this service talks to: the Nairon apps, the gateway,
 * local development, plus anything FRONTEND_URL adds (comma-separated).
 *
 * Moved out of main.ts unchanged (2026-10-01). CORS uses it as before; the
 * cross-app handoff (handoff/) uses it as the closed list of origins a
 * one-time code may be bound to — a code can never be addressed to a page
 * outside the estate.
 */
const BUILT_IN = [
  'http://localhost:3000',
  'http://localhost:3004',
  'http://localhost:4001',
  'http://localhost:4002',
  'http://localhost:4003',
  'http://localhost:4004',
  'https://gateway.nairon.am',
  'https://nairon.am',
  'https://www.nairon.am',
  'https://crm.nairon.am',
  'https://finance.nairon.am',
  'https://warehouse.nairon.am',
  'https://staging.nairon.am',
  'https://staging-crm.nairon.am',
  'https://staging-finance.nairon.am',
  'https://staging-warehouse.nairon.am',
];

export function browserOrigins(env: NodeJS.ProcessEnv = process.env): string[] {
  return [
    ...BUILT_IN,
    ...(env.FRONTEND_URL?.split(',').map((u) => u.trim()).filter(Boolean) ?? []),
  ].filter(Boolean);
}
