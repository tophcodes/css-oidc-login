export interface PendingLogin {
  codeVerifier: string;
}

export class PendingLoginStore {
  private readonly pending = new Map<string, { data: PendingLogin; expires: number }>();
  private readonly ttlMs: number;

  public constructor(ttlMs = 600000) {
    this.ttlMs = ttlMs;
  }

  public async create(state: string, data: PendingLogin): Promise<void> {
    this.pending.set(state, { data, expires: Date.now() + this.ttlMs });
  }

  public async consume(state: string): Promise<PendingLogin | undefined> {
    const entry = this.pending.get(state);
    this.pending.delete(state);
    if (!entry || entry.expires < Date.now()) {
      return undefined;
    }
    return entry.data;
  }
}
