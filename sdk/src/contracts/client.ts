import type { GITSDeployment } from '../types/config.js';

import { GITToken } from './git-token.js';
import { ShellRegistry } from './shell-registry.js';
import { GhostRegistry } from './ghost-registry.js';
import { SessionManager } from './session-manager.js';
import { ReceiptManager } from './receipt-manager.js';
import { RewardsManager } from './rewards-manager.js';
import { VerifierRegistry } from './verifier-registry.js';

export class GITSClient {
  public readonly deployment: GITSDeployment;

  public readonly git_token: GITToken;
  public readonly shell_registry: ShellRegistry;
  public readonly ghost_registry: GhostRegistry;
  public readonly session_manager: SessionManager;
  public readonly receipt_manager: ReceiptManager;
  public readonly rewards_manager: RewardsManager;
  public readonly verifier_registry: VerifierRegistry;

  constructor(deployment: GITSDeployment) {
    this.deployment = deployment;

    this.git_token = new GITToken(deployment.git_token);
    this.shell_registry = new ShellRegistry(deployment.shell_registry);
    this.ghost_registry = new GhostRegistry(deployment.ghost_registry);
    this.session_manager = new SessionManager(deployment.session_manager);
    this.receipt_manager = new ReceiptManager(deployment.receipt_manager);
    this.rewards_manager = new RewardsManager(deployment.rewards_manager);
    this.verifier_registry = new VerifierRegistry(deployment.verifier_registry);
  }
}

