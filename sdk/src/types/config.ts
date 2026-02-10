import type { Address } from 'viem';

export interface GITSDeployment {
  chain_id: bigint;
  git_token: Address;
  shell_registry: Address;
  ghost_registry: Address;
  session_manager: Address;
  receipt_manager: Address;
  rewards_manager: Address;
  verifier_registry: Address;
}

export interface GITSConfig {
  deployment: GITSDeployment;
}

