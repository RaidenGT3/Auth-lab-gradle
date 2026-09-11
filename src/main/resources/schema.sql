CREATE TABLE IF NOT EXISTS user_entities (
    id VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(200),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS user_credentials (
    credential_id VARCHAR(255) NOT NULL,
    user_entity_user_id VARCHAR(255) NOT NULL,
    public_key BLOB NOT NULL,
    signature_count BIGINT,
    uv_initialized BOOLEAN,
    backup_eligible BOOLEAN NOT NULL,
    authenticator_transports VARCHAR(1000),
    public_key_credential_type VARCHAR(100),
    backup_state BOOLEAN NOT NULL,
    attestation_object BLOB,
    attestation_client_data_json BLOB,
    created DATETIME,
    last_used DATETIME NULL,
    label VARCHAR(1000) NOT NULL,
    PRIMARY KEY (credential_id),
    CONSTRAINT fk_user_credentials_user_entity
        FOREIGN KEY (user_entity_user_id)
        REFERENCES user_entities(id)
);