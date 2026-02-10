import { describe, expect, it } from 'vitest';

import { heartbeatDigest } from '@gits-protocol/sdk';
import { encodeAbiParameters, recoverAddress } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { ShellDb } from '../src/storage/db.js';
import { HeartbeatService } from '../src/sessions/heartbeat.js';
import { Metrics } from '../src/telemetry/metrics.js';

function encodeSessionKey(pubkeyUncompressed: Hex): Hex {
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1, pubkeyUncompressed]);
}

describe('heartbeat', () => {
  it('co-signs valid heartbeat and stores interval', async () => {
    const db = new ShellDb({ filename: ':memory:' });
    const metrics = new Metrics();
    const svc = new HeartbeatService({ chainId: 1n, db, metrics });

    const ghost = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);
    const shell = privateKeyToAccount(('0x' + '22'.repeat(32)) as Hex);

    const sessionId = 123n;
    const epoch = 5n;
    const intervalIndex = 7n;

    svc.registerSession({
      sessionId,
      ghostSessionKey: encodeSessionKey(ghost.publicKey),
      shellSessionKey: encodeSessionKey(shell.publicKey),
    });
    svc.setShellSessionPrivateKey(sessionId, ('0x' + '22'.repeat(32)) as Hex);

    const digest = heartbeatDigest({ chain_id: 1n, session_id: sessionId, epoch, interval_index: intervalIndex });
    const sigGhost = await ghost.sign({ hash: digest });

    const res = await svc.handleHeartbeat({
      sessionId: sessionId.toString(),
      epoch: epoch.toString(),
      intervalIndex: intervalIndex.toString(),
      sigGhost,
    });

    expect(res.accepted).toBe(true);
    expect(res.sigShell).toBeDefined();

    const recoveredShell = await recoverAddress({ hash: digest, signature: res.sigShell! });
    expect(recoveredShell.toLowerCase()).toEqual(shell.address.toLowerCase());

    const row = db
      .raw()
      .prepare('SELECT vi FROM intervals WHERE session_id = ? AND epoch = ? AND interval_index = ?')
      .get(sessionId, epoch, Number(intervalIndex)) as { vi: number } | undefined;
    expect(row?.vi).toEqual(1);

    // Replay should be rejected and not create a second row.
    const replay = await svc.handleHeartbeat({
      sessionId: sessionId.toString(),
      epoch: epoch.toString(),
      intervalIndex: intervalIndex.toString(),
      sigGhost,
    });
    expect(replay.accepted).toBe(false);
    expect(replay.reason).toBe('replay');

    db.close();
  });
});

