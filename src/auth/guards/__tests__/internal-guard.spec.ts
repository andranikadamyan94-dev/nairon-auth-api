import { UnauthorizedException } from '@nestjs/common';

import { InternalGuard, assertInternalAuthConfigured, assertInternalSecret } from '../internal.guard';

/**
 * The exact bug, pinned so it cannot come back.
 *
 * auth-api's guard returned TRUE when INTERNAL_SECRET was absent, as a
 * deliberate rollout step that never got its second half. Every route behind
 * it carries @Public(), so the guard was the only authentication on: read
 * every account, create a user, delete a user, and assign any role to any
 * user. The first test below is that case.
 */

const withSecret = (value: string | undefined, run: () => void) => {
  const had = Object.prototype.hasOwnProperty.call(process.env, 'INTERNAL_SECRET');
  const previous = process.env.INTERNAL_SECRET;
  if (value === undefined) delete process.env.INTERNAL_SECRET;
  else process.env.INTERNAL_SECRET = value;
  try {
    run();
  } finally {
    if (had) process.env.INTERNAL_SECRET = previous as string;
    else delete process.env.INTERNAL_SECRET;
  }
};

/* A synthetic value. Never the real secret, and never read from the env. */
const TEST_SECRET = 'test-internal-secret-not-a-real-credential';

describe('auth-api internal authentication · the fail-open case', () => {
  it('DENIES when the expected secret is absent and no header is sent', () => {
    /*
     * The regression. `undefined !== undefined` was false, so the old code let
     * this through and created a transfer for an unauthenticated caller.
     */
    withSecret(undefined, () => {
      expect(() => assertInternalSecret(undefined)).toThrow(UnauthorizedException);
    });
  });

  it('DENIES when the expected secret is absent even with a header', () => {
    withSecret(undefined, () => {
      expect(() => assertInternalSecret('anything')).toThrow(UnauthorizedException);
    });
  });

  it('DENIES when the expected secret is blank', () => {
    withSecret('   ', () => {
      expect(() => assertInternalSecret('   ')).toThrow(UnauthorizedException);
      expect(() => assertInternalSecret(undefined)).toThrow(UnauthorizedException);
    });
  });
});

describe('auth-api internal authentication · the configured cases', () => {
  it('ALLOWS a correct header', () => {
    withSecret(TEST_SECRET, () => {
      expect(() => assertInternalSecret(TEST_SECRET)).not.toThrow();
    });
  });

  it.each([
    ['absent', undefined],
    ['empty', ''],
    ['whitespace', '   '],
    ['mismatched', 'not-the-secret'],
    ['malformed', 12345 as unknown as string],
    ['an array, as a duplicated header arrives', ['a', 'b'] as unknown as string],
  ])('DENIES a %s header', (_label, header) => {
    withSecret(TEST_SECRET, () => {
      expect(() => assertInternalSecret(header)).toThrow(UnauthorizedException);
    });
  });

  it('is the same rule through the guard', () => {
    const guard = new InternalGuard();
    const ctx = (header: unknown) =>
      ({
        switchToHttp: () => ({ getRequest: () => ({ headers: { 'x-internal-secret': header } }) }),
      }) as never;

    withSecret(TEST_SECRET, () => {
      expect(guard.canActivate(ctx(TEST_SECRET))).toBe(true);
      expect(() => guard.canActivate(ctx('wrong'))).toThrow(UnauthorizedException);
      expect(() => guard.canActivate(ctx(undefined))).toThrow(UnauthorizedException);
    });
    withSecret(undefined, () => {
      expect(() => guard.canActivate(ctx(undefined))).toThrow(UnauthorizedException);
    });
  });

  it('never puts the secret in the message it throws', () => {
    withSecret(TEST_SECRET, () => {
      try {
        assertInternalSecret('wrong');
        throw new Error('should have thrown');
      } catch (error) {
        expect(String((error as Error).message)).not.toContain(TEST_SECRET);
      }
    });
  });
});

describe('auth-api internal authentication · the second layer', () => {
  it('refuses to start without a secret', () => {
    withSecret(undefined, () => expect(() => assertInternalAuthConfigured()).toThrow(/INTERNAL_SECRET is not set/));
    withSecret('  ', () => expect(() => assertInternalAuthConfigured()).toThrow(/INTERNAL_SECRET is not set/));
  });

  it('starts when one is configured', () => {
    withSecret(TEST_SECRET, () => expect(() => assertInternalAuthConfigured()).not.toThrow());
  });
});
