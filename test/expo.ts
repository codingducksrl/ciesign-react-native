import { createHash } from 'node:crypto';

/** Stands in for the card; tests set `connect` and `sign` and inspect `closed`. */
export const card = {
  connect: async (_id: number, _pin: string): Promise<Uint8Array> => new Uint8Array(),
  sign: async (_id: number, _digestInfo: Uint8Array): Promise<Uint8Array> => new Uint8Array(),
  closed: [] as [number, string | null][],
};

export const requireNativeModule = () => ({
  sha256: async (data: Uint8Array) => new Uint8Array(createHash('sha256').update(data).digest()),
  connect: (id: number, pin: string) => card.connect(id, pin),
  sign: (id: number, digestInfo: Uint8Array) => card.sign(id, digestInfo),
  close: (id: number, error: string | null) => void card.closed.push([id, error]),
});
