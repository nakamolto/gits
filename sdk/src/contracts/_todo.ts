export function unimplemented(method: string): never {
  throw new Error(`TODO: ${method} (ABI-backed implementation pending)`);
}

