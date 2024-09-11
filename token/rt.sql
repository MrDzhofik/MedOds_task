CREATE TABLE refresh_tokens (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY ,
    user_id integer NOT NULL,
    refresh_token_hash text NOT NULL,
    ip_address text NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
