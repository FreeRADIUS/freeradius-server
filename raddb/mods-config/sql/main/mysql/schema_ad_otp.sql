--
-- Schema for AD OTP tokens (MySQL)
--

CREATE TABLE IF NOT EXISTS otp_tokens (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	serial VARCHAR(40) NOT NULL UNIQUE,
	tokentype VARCHAR(20) NOT NULL,

	secret_encrypted BLOB NOT NULL,
	secret_iv BINARY(16) NOT NULL,

	pin_hash VARCHAR(128),

	counter BIGINT UNSIGNED DEFAULT 0,

	otplen TINYINT UNSIGNED DEFAULT 6,
	timestep INT UNSIGNED DEFAULT 30,
	hashlib VARCHAR(10) DEFAULT 'sha1',

	count_window INT UNSIGNED DEFAULT 10,
	time_window INT UNSIGNED DEFAULT 180,
	sync_window INT UNSIGNED DEFAULT 1000,

	maxfail INT UNSIGNED DEFAULT 10,
	failcount INT UNSIGNED DEFAULT 0,
	active BOOLEAN DEFAULT TRUE,
	locked BOOLEAN DEFAULT FALSE,
	revoked BOOLEAN DEFAULT FALSE,

	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	last_auth DATETIME,
	auth_count INT UNSIGNED DEFAULT 0,

	INDEX idx_serial (serial),
	INDEX idx_tokentype (tokentype),
	INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS otp_token_assignment (
	token_id INT UNSIGNED NOT NULL PRIMARY KEY,
	ad_username VARCHAR(255) NOT NULL,
	ad_identifier_type VARCHAR(20) DEFAULT 'upn',
	ad_dn TEXT,
	realm VARCHAR(255),
	assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	assigned_by VARCHAR(255),

	UNIQUE KEY idx_username_realm (ad_username, realm),
	FOREIGN KEY (token_id) REFERENCES otp_tokens(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS otp_challenges (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	transaction_id VARCHAR(64) NOT NULL UNIQUE,
	serial VARCHAR(40) NOT NULL,
	challenge VARCHAR(512),
	data TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	expires_at DATETIME NOT NULL,
	received_count INT UNSIGNED DEFAULT 0,
	otp_valid BOOLEAN DEFAULT FALSE,

	INDEX idx_transaction (transaction_id),
	INDEX idx_serial (serial),
	INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS otp_audit (
	id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	action VARCHAR(50) NOT NULL,
	success BOOLEAN NOT NULL,
	serial VARCHAR(40),
	username VARCHAR(255),
	realm VARCHAR(255),
	client_ip VARCHAR(45),
	message TEXT,

	INDEX idx_timestamp (timestamp),
	INDEX idx_username (username),
	INDEX idx_serial (serial)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
