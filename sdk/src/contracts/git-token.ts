import type { Address } from 'viem';
import { unimplemented } from './_todo.js';

export class GITToken {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async mint(_to: Address, _amount: bigint): Promise<void> {
    return unimplemented('GITToken.mint');
  }

  async minter(): Promise<Address> {
    return unimplemented('GITToken.minter');
  }

  // ERC-20 surface (stubs).
  async name(): Promise<string> {
    return unimplemented('GITToken.name');
  }

  async symbol(): Promise<string> {
    return unimplemented('GITToken.symbol');
  }

  async decimals(): Promise<number> {
    return unimplemented('GITToken.decimals');
  }

  async totalSupply(): Promise<bigint> {
    return unimplemented('GITToken.totalSupply');
  }

  async balanceOf(_owner: Address): Promise<bigint> {
    return unimplemented('GITToken.balanceOf');
  }

  async allowance(_owner: Address, _spender: Address): Promise<bigint> {
    return unimplemented('GITToken.allowance');
  }

  async approve(_spender: Address, _amount: bigint): Promise<boolean> {
    return unimplemented('GITToken.approve');
  }

  async transfer(_to: Address, _amount: bigint): Promise<boolean> {
    return unimplemented('GITToken.transfer');
  }

  async transferFrom(_from: Address, _to: Address, _amount: bigint): Promise<boolean> {
    return unimplemented('GITToken.transferFrom');
  }
}

