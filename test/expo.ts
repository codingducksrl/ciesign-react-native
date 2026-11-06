type Messages = Record<string, string>;
type StepListener = (event: { id: number; step: 'detected' | 'pin' }) => void;

/** Stands in for the card; tests set `connect` and `sign`, inspect `closed`, and send native steps with `emit`. */
export const card = {
  connect: async (_id: number, _pin: string | null, _save: boolean, _messages: Messages): Promise<Uint8Array> => new Uint8Array(),
  sign: async (_id: number, _digestInfo: Uint8Array): Promise<Uint8Array> => new Uint8Array(),
  closed: [] as [number, string | null, string | null][],
  listeners: new Set<StepListener>(),
  emit: (id: number, step: 'detected' | 'pin') => card.listeners.forEach((listener) => listener({ id, step })),
};

export const requireNativeModule = () => ({
  connect: (id: number, pin: string | null, save: boolean, messages: Messages) => card.connect(id, pin, save, messages),
  sign: (id: number, digestInfo: Uint8Array) => card.sign(id, digestInfo),
  close: (id: number, error: string | null, done: string | null) => void card.closed.push([id, error, done]),
  addListener: (_event: 'onStep', listener: StepListener) => {
    card.listeners.add(listener);
    return { remove: () => card.listeners.delete(listener) };
  },
});
