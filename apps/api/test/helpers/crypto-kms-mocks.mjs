export function createMockConfig(overrides = {}) {
  const values = {
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-with-thirty-two-chars-min!!',
    KMS_PROVIDER: 'local',
    HSM_SLOT_INDEX: 0,
    HSM_KEY_LABEL: 'SDA-MASTER-KEK-v1',
    HSM_PIN: '000000',
    VAULT_ADDR: 'http://127.0.0.1:8200',
    VAULT_TOKEN: 'dev-mock-vault-token',
    VAULT_KEY_NAME: 'sda-document-kek',
    VAULT_TRANSIT_MOUNT: 'transit',
    AWS_KMS_KEY_ID: 'alias/sda-master-kek',
    AWS_KMS_REGION: 'us-east-1',
    ...overrides,
  };
  return {
    get: (key) => values[key],
  };
}
