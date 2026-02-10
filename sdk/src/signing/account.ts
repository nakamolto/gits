import type { LocalAccount } from 'viem/accounts';

// `LocalAccount`'s `sign` is optional at the type level (shared CustomSource surface),
// but the SDK's signing helpers require a hash-signing implementation.
export type LocalSignerAccount = LocalAccount & { sign: NonNullable<LocalAccount['sign']> };

