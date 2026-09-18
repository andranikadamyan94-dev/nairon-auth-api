/**
 * The authorization page's form-action, and why it names a second origin.
 *
 * A real connection failed on this. Chrome refused the last hop of the sign-in
 * — the 302 from /oauth/authorize to the client's callback — because
 * `form-action` governs the whole navigation a submit starts, redirects
 * included, and the policy allowed only `'self'`. Everything server-side had
 * already succeeded: the code was issued, the grant was stored, and the person
 * was left on a page that looked like the button had done nothing.
 *
 * So these tests hold both halves of the fix at once: the page names the one
 * callback this request was validated against, and it names nothing else.
 */
import { HttpStatus } from '@nestjs/common';

import { OAuthController, cspSource } from '../oauth.controller';

/** A Response that records what was set, in the shape express returns. */
function fakeRes() {
  const headers: Record<string, string> = {};
  const res: any = {
    statusCode: 200,
    body: '',
    status(code: number) { res.statusCode = code; return res; },
    setHeader(name: string, value: string) { headers[name.toLowerCase()] = value; return res; },
    send(body: string) { res.body = body; return res; },
    redirect(code: number, target: string) { res.statusCode = code; headers.location = target; return res; },
  };
  return { res, headers };
}

const REGISTERED = 'https://chatgpt.com/connector/oauth/M_5dvUF1IxNm';

const validated = {
  clientId: 'nairon-mcp-test',
  redirectUri: REGISTERED,
  scope: 'nairon:mcp offline_access',
  state: 'xyz',
};

function controller(over: Record<string, unknown> = {}) {
  const oauth: any = {
    validateAuthorizeRequest: jest.fn(async () => validated),
    openRequest: jest.fn(() => validated),
    sealRequest: jest.fn(() => 'sealed.ticket.value'),
    clientName: jest.fn(async () => 'ChatGPT'),
    authenticate: jest.fn(async () => ({ id: 18 })),
    workspacesFor: jest.fn(async () => [{ id: 4, name: 'Նաիրոն' }]),
    issueCode: jest.fn(async () => ({ code: 'one-time', state: 'xyz' })),
    ...over,
  };
  return { ctl: new OAuthController(oauth), oauth };
}

const policyOf = (headers: Record<string, string>) => headers['content-security-policy'] ?? '';
const formAction = (headers: Record<string, string>) =>
  (policyOf(headers).split(';').map((p) => p.trim()).find((p) => p.startsWith('form-action')) ?? '').replace('form-action ', '');

describe('cspSource', () => {
  it('keeps origin and path, which is all CSP reads', () => {
    expect(cspSource(REGISTERED)).toBe(REGISTERED);
  });

  it('drops a query string and a fragment rather than making the policy unparseable', () => {
    expect(cspSource('https://chatgpt.com/cb?state=x')).toBe('https://chatgpt.com/cb');
    expect(cspSource('https://chatgpt.com/cb#frag')).toBe('https://chatgpt.com/cb');
  });

  it('yields nothing for anything that is not an http(s) URI, so the policy can only narrow', () => {
    for (const value of [undefined, '', 'not a url', 'javascript:alert(1)', 'data:text/html,x', "https://a.test/cb' unsafe-inline"]) {
      const source = cspSource(value as string | undefined);
      expect(source === '' || source.startsWith('https://')).toBe(true);
    }
    expect(cspSource('javascript:alert(1)')).toBe('');
    expect(cspSource(undefined)).toBe('');
  });

  it('cannot smuggle a second source or a wildcard through a crafted URI', () => {
    // A URL parse never yields a space, so no extra source expression can be appended.
    expect(cspSource("https://evil.test/cb https://*")).not.toContain(' https://*');
    expect(cspSource('https://evil.test/*')).toBe('https://evil.test/*');
  });
});

describe('the authorization page policy', () => {
  it('names the validated callback beside self, and nothing else', async () => {
    const { ctl } = controller();
    const { res, headers } = fakeRes();

    await ctl.authorize({}, res);

    expect(formAction(headers)).toBe(`'self' ${REGISTERED}`);
    // The rest of the policy is untouched: nothing loads, nothing frames it.
    expect(policyOf(headers)).toContain("default-src 'none'");
    expect(policyOf(headers)).toContain("frame-ancestors 'none'");
    expect(policyOf(headers)).not.toContain('*');
    expect(policyOf(headers)).not.toContain('unsafe-eval');
  });

  it('keeps the policy on the re-render after a wrong password, so a retry can still finish', async () => {
    const { ctl } = controller({ authenticate: jest.fn(async () => { throw new Error('nope'); }) });
    const { res, headers } = fakeRes();

    await ctl.authorizeSubmit({ request: 'sealed', email: 'x@y.z', password: 'wrong' }, res, {} as never);

    expect(res.statusCode).toBe(HttpStatus.UNAUTHORIZED);
    expect(res.body).toContain('Սխալ էլ. փոստ կամ գաղտնաբառ');
    expect(formAction(headers)).toBe(`'self' ${REGISTERED}`);
  });

  it('names it on the workspace screen too, which is the form that finishes the flow', async () => {
    const { ctl } = controller({ workspacesFor: jest.fn(async () => [{ id: 4, name: 'A' }, { id: 8, name: 'B' }]) });
    const { res, headers } = fakeRes();

    await ctl.authorizeSubmit({ request: 'sealed', email: 'x@y.z', password: 'right' }, res, {} as never);

    expect(formAction(headers)).toBe(`'self' ${REGISTERED}`);
  });

  it('names no callback on an error page, where there is no form to submit', async () => {
    const { ctl } = controller({ validateAuthorizeRequest: jest.fn(async () => { throw new Error('unknown client_id'); }) });
    const { res, headers } = fakeRes();

    await ctl.authorize({}, res);

    expect(formAction(headers)).toBe("'self'");
  });

  it('is the request\'s own callback, not a value from the query string', async () => {
    const { ctl, oauth } = controller();
    const { res, headers } = fakeRes();

    await ctl.authorize({ redirect_uri: 'https://attacker.example/steal' }, res);

    // The header shows what validation returned; the query is only its input.
    expect(oauth.validateAuthorizeRequest).toHaveBeenCalled();
    expect(formAction(headers)).toBe(`'self' ${REGISTERED}`);
    expect(policyOf(headers)).not.toContain('attacker.example');
  });

  it('still redirects to the callback with the code, and carries no body there', async () => {
    const { ctl } = controller();
    const { res, headers } = fakeRes();

    await ctl.authorizeSubmit({ request: 'sealed', email: 'x@y.z', password: 'right' }, res, {} as never);

    // 302 answering a POST is fetched as a GET: the password cannot follow it.
    expect(res.statusCode).toBe(302);
    expect(headers.location).toContain(`${REGISTERED}?`);
    expect(headers.location).toContain('code=');
    expect(res.body).toBe('');
  });
});
