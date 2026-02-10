export { deriveVaultKey, encrypt, decrypt, type EncryptedVault } from './vaulting/encryptor.js';

export {
  encodeShare,
  decodeShare,
  splitVaultKey,
  reconstructVaultKey,
  gfAdd,
  gfMul,
  gfPow,
  gfInv,
  evalPolyAt,
  type ShamirShare,
} from './vaulting/shamir.js';

export { CheckpointPublisher, FileStorageBackend, type ShareReceipt, type RecoverySetMember } from './vaulting/checkpoint-publisher.js';
export { VaultManager, type VaultManagerConfig, type LatestCheckpoint } from './vaulting/vault-manager.js';

export { RecoveryConfigManager, type RecoveryConfig } from './recovery/recovery-config.js';
export { RecoveryMonitor, type RecoveryEvent, type RecoveryEventSource } from './recovery/recovery-monitor.js';
export { RecoveryClient } from './recovery/recovery-client.js';

