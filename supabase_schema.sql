-- ZTS database schema
-- Run this in the Supabase SQL Editor to set up all tables.

-- users
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'CustomerSupport'
        CHECK (role IN ('SuperAdmin','HR','Finance','IT','CustomerSupport')),
    is_active BOOLEAN DEFAULT TRUE,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- otp tokens
CREATE TABLE IF NOT EXISTS otp_tokens (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    otp_code TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

-- sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_active TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- trusted devices
CREATE TABLE IF NOT EXISTS trusted_devices (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    browser TEXT,
    os TEXT,
    ip_address TEXT,
    location TEXT,
    is_trusted BOOLEAN DEFAULT FALSE,
    risk_level TEXT DEFAULT 'medium'
        CHECK (risk_level IN ('low','medium','high','critical')),
    registered_at TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, fingerprint)
);

-- audit log
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    detail TEXT,
    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,
    risk_score INT DEFAULT 0,
    country TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- seed default users (password: Password1!)
INSERT INTO users (username, email, password_hash, role) VALUES
    ('superadmin', 'superadmin@zts.local',
     '$2b$12$LJ3m4ys3Lz0QxDOXOQxZxOq7lFcHnDOSsNqvGp/4.K6z5Z1gKZO6y', 'SuperAdmin'),
    ('hr_user', 'hr@zts.local',
     '$2b$12$LJ3m4ys3Lz0QxDOXOQxZxOq7lFcHnDOSsNqvGp/4.K6z5Z1gKZO6y', 'HR'),
    ('finance_user', 'finance@zts.local',
     '$2b$12$LJ3m4ys3Lz0QxDOXOQxZxOq7lFcHnDOSsNqvGp/4.K6z5Z1gKZO6y', 'Finance'),
    ('it_user', 'it@zts.local',
     '$2b$12$LJ3m4ys3Lz0QxDOXOQxZxOq7lFcHnDOSsNqvGp/4.K6z5Z1gKZO6y', 'IT'),
    ('cs_user', 'cs@zts.local',
     '$2b$12$LJ3m4ys3Lz0QxDOXOQxZxOq7lFcHnDOSsNqvGp/4.K6z5Z1gKZO6y', 'CustomerSupport')
ON CONFLICT (username) DO NOTHING;
