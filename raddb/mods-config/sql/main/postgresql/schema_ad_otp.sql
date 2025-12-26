--
-- Schema for AD OTP tokens (PostgreSQL)
--

CREATE TABLE IF NOT EXISTS otp_tokens (
	id SERIAL PRIMARY KEY,
	serial VARCHAR(40) NOT NULL UNIQUE,
	tokentype VARCHAR(20) NOT NULL CHECK (tokentype IN ('hotp', 'totp')),

	secret_encrypted BYTEA NOT NULL,
	secret_iv BYTEA NOT NULL,

	pin_hash VARCHAR(128),

	counter BIGINT DEFAULT 0,

	otplen SMALLINT DEFAULT 6 CHECK (otplen IN (6, 8)),
	timestep INTEGER DEFAULT 30,
	hashlib VARCHAR(10) DEFAULT 'sha1' CHECK (hashlib IN ('sha1', 'sha256', 'sha512')),

	count_window INTEGER DEFAULT 10,
	time_window INTEGER DEFAULT 180,
	sync_window INTEGER DEFAULT 1000,

	maxfail INTEGER DEFAULT 10,
	failcount INTEGER DEFAULT 0,
	active BOOLEAN DEFAULT TRUE,
	locked BOOLEAN DEFAULT FALSE,
	revoked BOOLEAN DEFAULT FALSE,

	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	last_auth TIMESTAMP,
	auth_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_otp_tokens_serial ON otp_tokens(serial);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_tokentype ON otp_tokens(tokentype);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_active ON otp_tokens(active);

CREATE TABLE IF NOT EXISTS otp_token_assignment (
	token_id INTEGER PRIMARY KEY REFERENCES otp_tokens(id) ON DELETE CASCADE,
	ad_username VARCHAR(255) NOT NULL,
	ad_identifier_type VARCHAR(20) DEFAULT 'upn' CHECK (ad_identifier_type IN ('upn', 'samaccountname', 'dn')),
	ad_dn TEXT,
	realm VARCHAR(255),
	assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	assigned_by VARCHAR(255),

	UNIQUE (ad_username, realm)
);

CREATE INDEX IF NOT EXISTS idx_otp_assignment_username ON otp_token_assignment(ad_username, realm);

CREATE TABLE IF NOT EXISTS otp_challenges (
	id SERIAL PRIMARY KEY,
	transaction_id VARCHAR(64) NOT NULL UNIQUE,
	serial VARCHAR(40) NOT NULL,
	challenge VARCHAR(512),
	data TEXT,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	expires_at TIMESTAMP NOT NULL,
	received_count INTEGER DEFAULT 0,
	otp_valid BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_otp_challenges_transaction ON otp_challenges(transaction_id);
CREATE INDEX IF NOT EXISTS idx_otp_challenges_serial ON otp_challenges(serial);
CREATE INDEX IF NOT EXISTS idx_otp_challenges_expires ON otp_challenges(expires_at);

CREATE TABLE IF NOT EXISTS otp_audit (
	id BIGSERIAL PRIMARY KEY,
	timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	action VARCHAR(50) NOT NULL,
	success BOOLEAN NOT NULL,
	serial VARCHAR(40),
	username VARCHAR(255),
	realm VARCHAR(255),
	client_ip VARCHAR(45),
	message TEXT
);

CREATE INDEX IF NOT EXISTS idx_otp_audit_timestamp ON otp_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_otp_audit_username ON otp_audit(username);
CREATE INDEX IF NOT EXISTS idx_otp_audit_serial ON otp_audit(serial);
