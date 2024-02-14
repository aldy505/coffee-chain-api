-- +goose Up
-- +goose StatementBegin
CREATE TABLE user_accounts
(
    id              BIGSERIAL PRIMARY KEY NOT NULL,
    name            VARCHAR(255)          NOT NULL,
    email           VARCHAR(255)          NOT NULL,
    hashed_password TEXT                  NOT NULL,
    gender          SMALLINT                       DEFAULT 0,
    type            SMALLINT                       DEFAULT 0,
    email_validated BOOLEAN               NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ           NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(63)           NOT NULL,
    updated_at      TIMESTAMPTZ           NOT NULL DEFAULT NOW(),
    updated_by      VARCHAR(63)           NOT NULL
);

CREATE UNIQUE INDEX unq_user_accounts_email ON user_accounts (email);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_accounts;
-- +goose StatementEnd
