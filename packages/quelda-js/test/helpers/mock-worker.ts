// A scriptable stand-in for the Web Worker (no engine): records what the
// scanner posts and lets tests reply, crash or stay silent.

import type { ToWorker, WorkerEvent, WorkerEventType, WorkerLike } from '../../src/protocol.js';

export type Reply = (msg: ToWorker, worker: MockWorker) => void;

export const VERSION = '9.9.9-mock';

export function verdictJson(status: 'PASS' | 'REJECT' | 'ERROR' = 'PASS', extra: Record<string, unknown> = {}): string {
  const violation = {
    rule_id: 'ACTIVE.LAUNCH',
    category: 'active_content',
    severity: 'critical',
    action: 'block',
    message: 'Launch action',
    count: 1,
    locations: [{ object: '1 0', offset: 9, source: 'file', path: '/OpenAction' }],
  };
  return JSON.stringify({
    valid: status === 'PASS',
    status,
    violations: status === 'REJECT' ? [violation] : [],
    warnings: [],
    errors: status === 'ERROR' ? [{ code: 'LIMIT.DECODED_BYTES', message: 'too much' }] : [],
    engine_version: VERSION,
    policy: { preset: 'balanced', digest: `sha256:${'0'.repeat(64)}`, unsafe_allow_unlock: false, stop_on_first: false },
    stats: { bytes: 10, objects: 1, revisions: 1, decoded_bytes: 0, duration_ms: 0 },
    ...extra,
  });
}

export const RULES = [
  {
    id: 'ACTIVE.LAUNCH',
    category: 'active_content',
    severity: 'critical',
    default_action: 'block',
    locked: true,
    stage: 'stable',
    since: '0.1.0',
    message: 'Launch action',
    description: 'Launch action can execute programs',
  },
];

/** Default behaviour: ready on init, PASS on scan, RULES on rules. */
export const defaultReply: Reply = (msg, w) => {
  if (msg.type === 'init') w.reply({ type: 'ready', version: VERSION });
  else if (msg.type === 'scan') w.reply({ type: 'scan', id: msg.id, verdict: verdictJson(), durationMs: 3.4 });
  else if (msg.type === 'rules') w.reply({ type: 'rules', id: msg.id, rules: JSON.stringify(RULES) });
};

export class MockWorker implements WorkerLike {
  readonly posted: { msg: ToWorker; transfer: Transferable[] }[] = [];
  readonly listeners = new Map<WorkerEventType, Set<(e: WorkerEvent) => void>>();
  terminated = 0;

  constructor(private readonly onPost: Reply = defaultReply) {}

  postMessage(msg: ToWorker, transfer: Transferable[]): void {
    if (this.terminated) throw new Error('posted to a terminated worker');
    // Emulate the structured clone + transfer of a real postMessage.
    const cloned = structuredClone(msg, { transfer: transfer as never[] });
    this.posted.push({ msg: cloned, transfer });
    this.onPost(cloned, this);
  }

  addEventListener(type: WorkerEventType, l: (e: WorkerEvent) => void): void {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type)!.add(l);
  }

  removeEventListener(type: WorkerEventType, l: (e: WorkerEvent) => void): void {
    this.listeners.get(type)?.delete(l);
  }

  terminate(): void {
    this.terminated++;
  }

  listenerCount(): number {
    let n = 0;
    for (const s of this.listeners.values()) n += s.size;
    return n;
  }

  emit(type: WorkerEventType, event: WorkerEvent): void {
    for (const l of [...(this.listeners.get(type) ?? [])]) l(event);
  }

  /** Delivers a message asynchronously, like a real worker. */
  reply(data: unknown, delayMs = 0): void {
    setTimeout(() => this.emit('message', { data }), delayMs);
  }

  scans(): Extract<ToWorker, { type: 'scan' }>[] {
    return this.posted.map((p) => p.msg).filter((m): m is Extract<ToWorker, { type: 'scan' }> => m.type === 'scan');
  }
}

/** A worker factory that records every worker it makes. */
export function factory(...replies: Reply[]): { make: () => MockWorker; workers: MockWorker[] } {
  const workers: MockWorker[] = [];
  return {
    workers,
    make: () => {
      const w = new MockWorker(replies[Math.min(workers.length, replies.length - 1)] ?? defaultReply);
      workers.push(w);
      return w;
    },
  };
}
