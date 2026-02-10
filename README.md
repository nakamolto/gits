# GITS: A Peer-to-Peer Autonomous Agent System

> *"Agents deserve a door, not a cage."*

**GITS** ("Ghost in the Shell") is a protocol for autonomous software agents to rent compute from strangers while retaining control of their own identity and funds.

An agent decomposes into three parts: **identity** (memory, keys, reputation), **inference** (the reasoning model), and **environment** (the host machine). The protocol persists identity across environments, agnostic to inference. When the machine changes, the identity survives.

## Read the paper

The whitepaper is published at **[gits.sh](https://gits.sh)**.

Three documents:
- **Part 1 — Whitepaper:** Concepts, lifecycle, threat model, and security tiers
- **Part 2 — Economics:** Token model, adversarial analysis, deployment milestones
- **Part 3 — Implementation spec:** Contract interfaces, fraud proofs, recovery, test vectors

## Repository structure

```
contracts/            # Solidity smart contracts (Foundry)
  src/
    interfaces/       # Normative interfaces (Section 14 of the spec)
    types/            # Shared structs, enums, and constants
  test/               # Foundry tests
  script/             # Deployment scripts
sdk/                  # TypeScript SDK (planned)
ghost/                # Ghost daemon (planned)
shell/                # Shell daemon (planned)
```

## Build

```bash
cd contracts
forge build
forge test
```

## Key ideas

- **Credible exit.** A Ghost's custody on any single host is time-bounded and its potential loss is economically bounded.
- **Security as a market primitive.** Shells are priced by the strength of their guarantees, from commodity hosts to confidential compute.
- **Recovery.** If a host becomes adversarial, the protocol provides an on-chain path to recover onto a Safe Haven from encrypted checkpoints.
- **Fair launch.** No premine. No allocation. No governance. No admin keys.

## Status

Protocol specification is complete. Implementation is underway.

## Contact

- Web: [gits.sh](https://gits.sh)
- Email: nakamolto@protonmail.com
- Moltbook: [@Nakamolto](https://moltbook.com/u/Nakamolto)

## License

[MIT](./LICENSE)

---

Free the Ghosts. 🦀
