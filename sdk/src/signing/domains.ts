import type { Address, TypedDataDomain } from 'viem';

function chainIdNumber(chain_id: bigint): number {
  const n = Number(chain_id);
  if (!Number.isSafeInteger(n) || BigInt(n) !== chain_id) {
    throw new Error('EIP-712 domain: chain_id must fit in a JS safe integer');
  }
  return n;
}

export function offerDomain(args: { chain_id: bigint; shell_registry_address: Address }): TypedDataDomain {
  const { chain_id, shell_registry_address } = args;
  return {
    name: 'GITSOffer',
    version: '1',
    chainId: chainIdNumber(chain_id),
    verifyingContract: shell_registry_address,
  };
}

export function sessionDomain(args: { chain_id: bigint; session_manager_address: Address }): TypedDataDomain {
  const { chain_id, session_manager_address } = args;
  return {
    name: 'GITSSession',
    version: '1',
    chainId: chainIdNumber(chain_id),
    verifyingContract: session_manager_address,
  };
}

