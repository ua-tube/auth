-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" VARCHAR(64) NOT NULL,
    "password" TEXT NOT NULL,
    "created_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(6) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_sessions" (
    "id" UUID NOT NULL,
    "ip" VARCHAR(64) NOT NULL,
    "user_agent" TEXT NOT NULL,
    "refresh_token" TEXT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recovery_tokens" (
    "id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "user_id" UUID NOT NULL,
    "expires_at" TIMESTAMP(6) NOT NULL,

    CONSTRAINT "recovery_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "user_sessions_user_id_idx" ON "user_sessions" USING HASH ("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_sessions_user_agent_user_id_key" ON "user_sessions"("user_agent", "user_id");

-- CreateIndex
CREATE UNIQUE INDEX "recovery_tokens_user_id_key" ON "recovery_tokens"("user_id");

-- AddForeignKey
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recovery_tokens" ADD CONSTRAINT "recovery_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
