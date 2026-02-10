import { describe, expect, it, vi } from 'vitest';

import { recoverAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import type { RBC } from '@gits-protocol/sdk';
import { recoverAuthDigest, shareAckDigest, shareDigest } from '@gits-protocol/sdk';

import { ShellDb } from '../src/storage/db.js';

import {
  ActiveRecoveryInitiatorError,
  ChainIdMismatchError,
  NoShareError,
  SafeHaven,
  SqliteShamirShareStore,
  ThresholdNotMetError,
  createAuthorizeHandler,
} from '../src/recovery/safe-haven.js';

function bytes32(hexByte: string): `0x${string}` {
  return (`0x${hexByte.repeat(32)}`) as `0x${string}`;
}

describe('Safe Haven', () => {
  it('stores, retrieves, purges Shamir shares', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const ghost_id = bytes32('11');
      const s1 = new Uint8Array([1, 2, 3]);
      const s2 = new Uint8Array([4, 5]);

      store.receiveShare(ghost_id, 2, s2, 101);
      store.receiveShare(ghost_id, 1, s1, 100);

      const rows = store.getShares(ghost_id);
      expect(rows.map((r) => r.share_index)).toEqual([1, 2]);
      expect(rows[0].encrypted_share).toEqual(s1);
      expect(rows[1].encrypted_share).toEqual(s2);

      store.purgeShares(ghost_id);
      expect(store.getShares(ghost_id)).toEqual([]);
    } finally {
      db.close();
    }
  });

  it('participates as RS member: AuthSig + ShareReceipt use correct digests and keys', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const chain_id = 31337n;
      const ghost_id = bytes32('22');
      const shell_id = bytes32('aa');

      const attempt_id = 7n;
      const checkpoint_commitment = bytes32('33');
      const envelope_commitment = bytes32('44');
      const pk_new = '0xaabbccdd' as `0x${string}`;

      const encrypted = new Uint8Array([9, 9, 9]);
      store.receiveShare(ghost_id, 1, encrypted, 123);

      const decryptShare = vi.fn(async (b: Uint8Array) => Uint8Array.from(b));

      const attempts = {
        getRecoveryAttempt: vi.fn(async () => ({
          checkpoint_commitment,
          envelope_commitment,
        })),
      };

      const sh = new SafeHaven({
        chain_id,
        shell_id,
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts,
        decryptShare,
      });

      const rbc: RBC = {
        ghost_id,
        attempt_id,
        checkpoint_commitment,
        pk_new,
        pk_transport: '0x1234',
        measurement_hash: bytes32('55'),
        tcb_min: bytes32('66'),
        valid_to: 0n,
        sigs_verifiers: [],
      };

      const resp = await sh.authorizeRecovery({
        chain_id,
        ghost_id,
        attempt_id,
        checkpoint_commitment,
        pk_new,
        rbc,
      });

      expect(decryptShare).toHaveBeenCalledTimes(1);

      const authHash = recoverAuthDigest({ chain_id, ghost_id, attempt_id, checkpoint_commitment, pk_new });
      const recoveredAuth = await recoverAddress({ hash: authHash, signature: resp.auth_sig.signature });
      expect(recoveredAuth).toBe(identity.address);

      const shareHash = shareDigest({ chain_id, ghost_id, attempt_id, checkpoint_commitment, envelope_commitment });
      const recoveredShare = await recoverAddress({ hash: shareHash, signature: resp.share_receipt.sig_shell });
      expect(recoveredShare).toBe(identity.address);

      const ackHash = shareAckDigest({ chain_id, ghost_id, attempt_id, checkpoint_commitment, envelope_commitment });
      const recoveredAck = await recoverAddress({ hash: ackHash, signature: resp.share_receipt.sig_ack });
      expect(recoveredAck).toBe(recovery.address);
    } finally {
      db.close();
    }
  });

  it('initiates recovery: startRecovery -> collect threshold -> recoveryRotate', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const chain_id = 1n;
      const ghost_id = bytes32('77');
      const shell_id = bytes32('88');
      const checkpoint_commitment = bytes32('99');
      const envelope_commitment = bytes32('aa');
      const pk_new = '0xdeadbeef' as `0x${string}`;

      const sh = new SafeHaven({
        chain_id,
        shell_id,
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts: { getRecoveryAttempt: async () => ({ checkpoint_commitment, envelope_commitment }) },
        decryptShare: async (b) => b,
      });

      const session_manager = {
        startRecovery: vi.fn(async () => 11n),
        recoveryRotate: vi.fn(async () => undefined),
        isActiveRecoveryInitiator: vi.fn(async () => false),
      };

      const rs_list = [bytes32('01'), bytes32('02'), bytes32('03')];
      const rbc: RBC = {
        ghost_id,
        attempt_id: 0n,
        checkpoint_commitment,
        pk_new,
        pk_transport: '0x1234',
        measurement_hash: bytes32('55'),
        tcb_min: bytes32('66'),
        valid_to: 0n,
        sigs_verifiers: [],
      };

      const mkResp = (member: `0x${string}`) => ({
        auth_sig: { shell_id: member, signature: '0x01' as `0x${string}` },
        share_receipt: { shell_id: member, sig_shell: '0x02' as `0x${string}`, sig_ack: '0x03' as `0x${string}` },
        decrypted_share: { share_index: 1, share: '0x04' as `0x${string}` },
      });

      const requestAuth = vi.fn(async (member: `0x${string}`) => mkResp(member));

      await sh.initiateRecovery({
        ghost_id,
        checkpoint_commitment,
        pk_new,
        rbc,
        rs_list,
        threshold: 2,
        session_manager,
        requestAuth,
      });

      expect(session_manager.startRecovery).toHaveBeenCalledTimes(1);
      expect(session_manager.recoveryRotate).toHaveBeenCalledTimes(1);

      const [_ghost, attempt_id] = (session_manager.recoveryRotate as any).mock.calls[0];
      expect(attempt_id).toBe(11n);
    } finally {
      db.close();
    }
  });

  it('unbonding guard blocks when active recovery initiator', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);
      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const sh = new SafeHaven({
        chain_id: 1n,
        shell_id: bytes32('aa'),
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts: { getRecoveryAttempt: async () => ({ checkpoint_commitment: bytes32('00'), envelope_commitment: bytes32('00') }) },
        decryptShare: async (b) => b,
      });

      await expect(
        sh.assertCanUnbondSafeHaven({
          startRecovery: async () => 0n,
          recoveryRotate: async () => undefined,
          isActiveRecoveryInitiator: async () => true,
        }),
      ).rejects.toBeInstanceOf(ActiveRecoveryInitiatorError);
    } finally {
      db.close();
    }
  });

  it('coordination endpoint handler returns expected shape', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const chain_id = 1n;
      const ghost_id = bytes32('22');
      const shell_id = bytes32('aa');
      const attempt_id = 1n;
      const checkpoint_commitment = bytes32('33');
      const envelope_commitment = bytes32('44');
      const pk_new = '0xaabbccdd' as `0x${string}`;

      store.receiveShare(ghost_id, 1, new Uint8Array([1]), 0);

      const sh = new SafeHaven({
        chain_id,
        shell_id,
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts: { getRecoveryAttempt: async () => ({ checkpoint_commitment, envelope_commitment }) },
        decryptShare: async (b) => b,
      });

      const handler = createAuthorizeHandler(sh);

      const rbc: RBC = {
        ghost_id,
        attempt_id,
        checkpoint_commitment,
        pk_new,
        pk_transport: '0x1234',
        measurement_hash: bytes32('55'),
        tcb_min: bytes32('66'),
        valid_to: 0n,
        sigs_verifiers: [],
      };

      const resp = await handler({ chain_id, ghost_id, attempt_id, checkpoint_commitment, pk_new, rbc });
      expect(resp).toHaveProperty('auth_sig');
      expect(resp).toHaveProperty('share_receipt');
      expect(resp).toHaveProperty('decrypted_share');
    } finally {
      db.close();
    }
  });

  it('member flow errors when no share present', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const chain_id = 1n;
      const ghost_id = bytes32('22');
      const shell_id = bytes32('aa');
      const attempt_id = 1n;
      const checkpoint_commitment = bytes32('33');
      const envelope_commitment = bytes32('44');
      const pk_new = '0xaabbccdd' as `0x${string}`;

      const sh = new SafeHaven({
        chain_id,
        shell_id,
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts: { getRecoveryAttempt: async () => ({ checkpoint_commitment, envelope_commitment }) },
        decryptShare: async (b) => b,
      });

      const rbc: RBC = {
        ghost_id,
        attempt_id,
        checkpoint_commitment,
        pk_new,
        pk_transport: '0x1234',
        measurement_hash: bytes32('55'),
        tcb_min: bytes32('66'),
        valid_to: 0n,
        sigs_verifiers: [],
      };

      await expect(sh.authorizeRecovery({ chain_id, ghost_id, attempt_id, checkpoint_commitment, pk_new, rbc })).rejects.toBeInstanceOf(
        NoShareError,
      );
    } finally {
      db.close();
    }
  });

  it('member flow errors on chain_id mismatch (prevents cross-chain signing)', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const ghost_id = bytes32('22');
      const attempt_id = 1n;
      const checkpoint_commitment = bytes32('33');
      const envelope_commitment = bytes32('44');
      const pk_new = '0xaabbccdd' as `0x${string}`;

      store.receiveShare(ghost_id, 1, new Uint8Array([1]), 0);

      const sh = new SafeHaven({
        chain_id: 1n,
        shell_id: bytes32('aa'),
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts: { getRecoveryAttempt: async () => ({ checkpoint_commitment, envelope_commitment }) },
        decryptShare: async (b) => b,
      });

    const rbc: RBC = {
      ghost_id,
      attempt_id,
      checkpoint_commitment,
      pk_new,
      pk_transport: '0x1234',
      measurement_hash: bytes32('55'),
      tcb_min: bytes32('66'),
      valid_to: 0n,
      sigs_verifiers: [],
    };

    await expect(
      sh.authorizeRecovery({
        chain_id: 2n,
        ghost_id,
        attempt_id,
        checkpoint_commitment,
        pk_new,
        rbc,
      }),
    ).rejects.toBeInstanceOf(ChainIdMismatchError);
    } finally {
      db.close();
    }
  });

  it('initiator flow errors when threshold not met', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    try {
      const store = new SqliteShamirShareStore(db);

      const identity = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const recovery = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');

      const chain_id = 1n;
      const ghost_id = bytes32('77');
      const shell_id = bytes32('88');
      const checkpoint_commitment = bytes32('99');
      const envelope_commitment = bytes32('aa');
      const pk_new = '0xdeadbeef' as `0x${string}`;

      const sh = new SafeHaven({
        chain_id,
        shell_id,
        identity_account: identity,
        recovery_account: recovery,
        store,
        attempts: { getRecoveryAttempt: async () => ({ checkpoint_commitment, envelope_commitment }) },
        decryptShare: async (b) => b,
      });

      const session_manager = {
        startRecovery: vi.fn(async () => 11n),
        recoveryRotate: vi.fn(async () => undefined),
        isActiveRecoveryInitiator: vi.fn(async () => false),
      };

      const rs_list = [bytes32('01'), bytes32('02')];
      const rbc: RBC = {
        ghost_id,
        attempt_id: 0n,
        checkpoint_commitment,
        pk_new,
        pk_transport: '0x1234',
        measurement_hash: bytes32('55'),
        tcb_min: bytes32('66'),
        valid_to: 0n,
        sigs_verifiers: [],
      };

      const requestAuth = vi.fn(async () => {
        throw new Error('offline');
      });

      await expect(
        sh.initiateRecovery({
          ghost_id,
          checkpoint_commitment,
          pk_new,
          rbc,
          rs_list,
          threshold: 2,
          session_manager,
          requestAuth,
        }),
      ).rejects.toBeInstanceOf(ThresholdNotMetError);
    } finally {
      db.close();
    }
  });
});
