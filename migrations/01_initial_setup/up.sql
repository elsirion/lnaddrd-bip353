-- payment_addresses table
CREATE TABLE IF NOT EXISTS payment_addresses (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    payment_uri TEXT NOT NULL,
    payment_uri_type VARCHAR(255) NOT NULL,
    password_hash BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (username, domain)
);

CREATE INDEX domain_users ON payment_addresses (domain, username);