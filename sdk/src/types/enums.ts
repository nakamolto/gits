// Mirrors `contracts/src/types/GITSTypes.sol` exactly.

export enum SessionMode {
  NORMAL = 0,
  STRANDED = 1,
  RECOVERY_LOCKED = 2,
  RECOVERY_STABILIZING = 3,
}

export enum StrandedReason {
  NO_SESSION = 0,
  VOLUNTARY_CLOSE = 1,
  EXPIRED = 2,
}

export enum BondStatus {
  BONDED = 0,
  UNBONDING = 1,
  WITHDRAWN = 2,
}

export enum RecoveryStatus {
  ACTIVE = 0,
  ROTATED = 1,
  EXPIRED = 2,
}

