import { createPublicClient, createWalletClient, http, parseAbi } from 'viem';
import type { Address, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import type { ShellConfig } from '../config/config.js';

const ERC20_ABI = parseAbi([
  'function approve(address spender, uint256 amount) external returns (bool)',
  'function allowance(address owner, address spender) external view returns (uint256)',
]);

const SHELL_REGISTRY_ABI = parseAbi([
  'function registerShell(bytes32 shell_id, bytes identity_pubkey, bytes offer_signer_pubkey, address payout_address, bytes32 salt, address bond_asset, uint256 bond_amount, bytes cert, bytes[] sigs_cert, bytes sig) external',
  'function registry_nonce() external view returns (uint64)',
  'function currentEpoch() external view returns (uint256)',
  'function GENESIS_TIME() external view returns (uint256)',
  'function EPOCH_LEN() external view returns (uint256)',
  'function assuranceTier(bytes32 shell_id) external view returns (uint8)',
  'function beginUnbond(bytes32 shell_id, uint256 amount) external',
  'function finalizeUnbond(bytes32 shell_id) external',
  'function bondSafeHaven(bytes32 shell_id, uint256 amount) external',
  'function beginUnbondSafeHaven(bytes32 shell_id) external',
  'function finalizeUnbondSafeHaven(bytes32 shell_id) external',
  'function setCertificate(bytes32 shell_id, bytes cert_data, bytes[] sigs_verifiers) external',
  'function revokeCertificate(bytes32 shell_id) external',
  'function proposeOfferSignerUpdate(bytes32 shell_id, bytes new_offer_signer_pubkey) external',
  'function confirmOfferSignerUpdate(bytes32 shell_id) external',
  'function proposeIdentityKeyUpdate(bytes32 shell_id, bytes new_identity_pubkey, bytes proof) external',
  'function confirmIdentityKeyUpdate(bytes32 shell_id) external',
  'function shell_key_nonce(bytes32 shell_id) external view returns (uint64)',
]);

const SESSION_MANAGER_ABI = parseAbi([
  'function getSessionKeys(uint256 session_id) external view returns (bytes ghost_key, bytes shell_key, address submitter)',
  'function isActiveRecoveryInitiator(bytes32 shell_id) external view returns (bool)',
  'event SessionOpened(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id)',
  'event SessionClosed(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id)',
]);

const RECEIPT_MANAGER_ABI = parseAbi([
  'function submitReceiptCandidate(uint256 session_id, uint256 epoch, tuple(bytes32 log_root, uint32 su_delivered, bytes log_ptr) candidate) external payable',
  'function publishReceiptLog(uint256 session_id, uint256 epoch, uint256 candidate_id, bytes encoded_log) external',
  'function N() external view returns (uint256)',
  'function B_RECEIPT() external view returns (uint256)',
  'event DAChallenged(uint256 indexed session_id, uint256 indexed epoch, uint256 candidate_id, address challenger)',
  'event ReceiptFinalized(uint256 indexed session_id, uint256 indexed epoch, bytes32 receipt_id, uint32 su_delivered, address submitter, uint256 weight_q)',
  'event CandidateSubmitted(uint256 indexed session_id, uint256 indexed epoch, uint256 candidate_id, address submitter, uint32 su_delivered)',
]);

export class ChainSubmitter {
  public readonly cfg: ShellConfig;
  public readonly account: ReturnType<typeof privateKeyToAccount>;
  public readonly publicClient: ReturnType<typeof createPublicClient>;
  public readonly walletClient: any;

  constructor(args: { cfg: ShellConfig; identityPrivateKey: Hex }) {
    this.cfg = args.cfg;
    this.account = privateKeyToAccount(args.identityPrivateKey);

    const transport = http(this.cfg.chain.rpcUrl);
    this.publicClient = createPublicClient({ transport });
    // viem's generics require a full Chain object for strongly-typed writeContract calls.
    // For v1, keep it simple and treat the wallet client as untyped.
    this.walletClient = createWalletClient({ transport, account: this.account }) as any;
  }

  async readRegistryNonce(): Promise<bigint> {
    const n = (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'registry_nonce',
    })) as bigint;
    return n;
  }

  async readCurrentEpoch(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'currentEpoch',
    })) as bigint;
  }

  async readAssuranceTier(shellId: Hex): Promise<number> {
    const tier = (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'assuranceTier',
      args: [shellId],
    })) as number | bigint;
    return Number(tier);
  }

  async readIntervalsPerEpoch(): Promise<number> {
    const n = (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.receiptManager,
      abi: RECEIPT_MANAGER_ABI,
      functionName: 'N',
    })) as bigint;
    return Number(n);
  }

  async readReceiptBond(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.receiptManager,
      abi: RECEIPT_MANAGER_ABI,
      functionName: 'B_RECEIPT',
    })) as bigint;
  }

  async readSessionKeys(sessionId: bigint): Promise<{ ghostKey: Hex; shellKey: Hex; submitter: Address }> {
    const [ghostKey, shellKey, submitter] = (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.sessionManager,
      abi: SESSION_MANAGER_ABI,
      functionName: 'getSessionKeys',
      args: [sessionId],
    })) as [Hex, Hex, Address];
    return { ghostKey, shellKey, submitter };
  }

  async approveErc20(args: { asset: Address; spender: Address; amount: bigint }): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: args.asset,
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [args.spender, args.amount],
    })) as Hex;
  }

  async registerShell(args: {
    shellId: Hex;
    identityPubkey: Hex;
    offerSignerPubkey: Hex;
    payoutAddress: Address;
    salt: Hex;
    bondAsset: Address;
    bondAmount: bigint;
    cert: Hex;
    sigsCert: Hex[];
    sig: Hex;
  }): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'registerShell',
      args: [
        args.shellId,
        args.identityPubkey,
        args.offerSignerPubkey,
        args.payoutAddress,
        args.salt,
        args.bondAsset,
        args.bondAmount,
        args.cert,
        args.sigsCert,
        args.sig,
      ],
    })) as Hex;
  }

  async readShellKeyNonce(shellId: Hex): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'shell_key_nonce',
      args: [shellId],
    })) as bigint;
  }

  async proposeOfferSignerUpdate(args: { shellId: Hex; newOfferSignerPubkey: Hex }): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'proposeOfferSignerUpdate',
      args: [args.shellId, args.newOfferSignerPubkey],
    })) as Hex;
  }

  async confirmOfferSignerUpdate(shellId: Hex): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'confirmOfferSignerUpdate',
      args: [shellId],
    })) as Hex;
  }

  async proposeIdentityKeyUpdate(args: { shellId: Hex; newIdentityPubkey: Hex; proof: Hex }): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'proposeIdentityKeyUpdate',
      args: [args.shellId, args.newIdentityPubkey, args.proof],
    })) as Hex;
  }

  async confirmIdentityKeyUpdate(shellId: Hex): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'confirmIdentityKeyUpdate',
      args: [shellId],
    })) as Hex;
  }

  async beginUnbond(shellId: Hex, amount: bigint): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'beginUnbond',
      args: [shellId, amount],
    })) as Hex;
  }

  async finalizeUnbond(shellId: Hex): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'finalizeUnbond',
      args: [shellId],
    })) as Hex;
  }

  async bondSafeHaven(shellId: Hex, amount: bigint): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'bondSafeHaven',
      args: [shellId, amount],
    })) as Hex;
  }

  async beginUnbondSafeHaven(shellId: Hex): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'beginUnbondSafeHaven',
      args: [shellId],
    })) as Hex;
  }

  async finalizeUnbondSafeHaven(shellId: Hex): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'finalizeUnbondSafeHaven',
      args: [shellId],
    })) as Hex;
  }

  async isActiveRecoveryInitiator(shellId: Hex): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.cfg.chain.deployment.sessionManager,
      abi: SESSION_MANAGER_ABI,
      functionName: 'isActiveRecoveryInitiator',
      args: [shellId],
    })) as boolean;
  }

  async setCertificate(shellId: Hex, certData: Hex, sigsVerifiers: Hex[]): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'setCertificate',
      args: [shellId, certData, sigsVerifiers],
    })) as Hex;
  }

  async revokeCertificate(shellId: Hex): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.shellRegistry,
      abi: SHELL_REGISTRY_ABI,
      functionName: 'revokeCertificate',
      args: [shellId],
    })) as Hex;
  }

  async submitReceiptCandidate(args: {
    sessionId: bigint;
    epoch: bigint;
    candidate: { logRoot: Hex; suDelivered: number; logPtr: Hex };
    value: bigint;
  }): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.receiptManager,
      abi: RECEIPT_MANAGER_ABI,
      functionName: 'submitReceiptCandidate',
      args: [
        args.sessionId,
        args.epoch,
        { log_root: args.candidate.logRoot, su_delivered: args.candidate.suDelivered, log_ptr: args.candidate.logPtr },
      ],
      value: args.value,
    })) as Hex;
  }

  async publishReceiptLog(args: { sessionId: bigint; epoch: bigint; candidateId: bigint; encodedLog: Hex }): Promise<Hex> {
    return (await this.walletClient.writeContract({
      address: this.cfg.chain.deployment.receiptManager,
      abi: RECEIPT_MANAGER_ABI,
      functionName: 'publishReceiptLog',
      args: [args.sessionId, args.epoch, args.candidateId, args.encodedLog],
    })) as Hex;
  }
}

export const ABIS = {
  ERC20_ABI,
  SHELL_REGISTRY_ABI,
  SESSION_MANAGER_ABI,
  RECEIPT_MANAGER_ABI,
} as const;
