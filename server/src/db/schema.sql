-- Initial database schema for ldap-fido-server

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(200),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for faster lookups
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_display_name ON users(display_name);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(32) UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT unique_user_id UNIQUE (user_id)
);

-- Index for faster user role lookups
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);

-- Insert default roles
INSERT INTO roles (name) VALUES ('admin'), ('user'), ('auditor') ON CONFLICT DO NOTHING;

-- Application variables table
CREATE TABLE app_variables (
    service VARCHAR(32) NOT NULL, -- e.g. 'ldap', 'redis', 'database', 'app', etc.
    key VARCHAR(64) NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (service, key)
);

-- WebAuthn challenges for registration and authentication
CREATE TABLE webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    challenge TEXT NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('registration', 'authentication')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT fk_webauthn_challenge_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Index for faster challenge lookups
CREATE INDEX idx_webauthn_challenges_user_type ON webauthn_challenges(user_id, type);

-- WebAuthn authenticators for users
CREATE TABLE authenticators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    credential_id TEXT NOT NULL,
    credential_public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports TEXT[],
    name VARCHAR(255) NOT NULL DEFAULT 'Security Key',
    ssh_key_type VARCHAR(64) CHECK (ssh_key_type IN ('sk-ecdsa-sha2-nistp256@openssh.com', 'sk-ssh-ed25519@openssh.com')),
    ssh_uploaded_at TIMESTAMPTZ,
    ssh_comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    CONSTRAINT fk_authenticator_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE,
    CONSTRAINT uq_credential_id UNIQUE (credential_id),
    CONSTRAINT one_authenticator_per_user UNIQUE (user_id)
);

-- Indexes for faster lookups
CREATE INDEX idx_authenticators_user_id ON authenticators(user_id);
CREATE INDEX idx_authenticators_credential_id ON authenticators(credential_id);
CREATE INDEX idx_authenticators_ssh_key_type ON authenticators(ssh_key_type);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update updated_at on authenticators
CREATE TRIGGER update_authenticators_updated_at
BEFORE UPDATE ON authenticators
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Function to update last_used_at when counter changes
CREATE OR REPLACE FUNCTION update_authenticator_last_used()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.counter <> NEW.counter THEN
        NEW.last_used_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update last_used_at on counter update
CREATE TRIGGER update_authenticator_last_used_trigger
BEFORE UPDATE OF counter ON authenticators
FOR EACH ROW
WHEN (OLD.counter IS DISTINCT FROM NEW.counter)
EXECUTE FUNCTION update_authenticator_last_used();

-- SSH stub download tokens (single-use, short-lived)
CREATE TABLE stub_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL,
    credential_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    issuer_ip INET,
    CONSTRAINT fk_stub_token_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Indexes for token lookups
CREATE INDEX idx_stub_tokens_token_hash ON stub_tokens(token_hash);
CREATE INDEX idx_stub_tokens_user_id ON stub_tokens(user_id);
CREATE INDEX idx_stub_tokens_expires_at ON stub_tokens(expires_at);
