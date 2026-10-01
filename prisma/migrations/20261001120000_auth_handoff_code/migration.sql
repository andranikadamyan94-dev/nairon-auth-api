-- SSO handoff hardening (2026-10-01): one-time cross-app sign-in codes.
-- Additive and unused while AUTH_HANDOFF_CODES_ENABLED is off. Rows live about
-- a minute; the service prunes expired ones as it issues new ones. Rollback
-- needs nothing: an unused empty table is harmless, and DROP TABLE is safe.
CREATE TABLE IF NOT EXISTS "AuthHandoffCode" (
    "codeHash" TEXT NOT NULL,
    "userId" INTEGER NOT NULL,
    "targetOrigin" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthHandoffCode_pkey" PRIMARY KEY ("codeHash")
);

CREATE INDEX IF NOT EXISTS "AuthHandoffCode_expiresAt_idx" ON "AuthHandoffCode"("expiresAt");
CREATE INDEX IF NOT EXISTS "AuthHandoffCode_userId_idx" ON "AuthHandoffCode"("userId");
