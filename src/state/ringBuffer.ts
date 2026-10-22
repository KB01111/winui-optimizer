/**
 * Fixed-capacity ring buffer. Pushing past capacity silently drops the oldest
 * entry, which is what keeps the live feed bounded at high event volume.
 */
export class RingBuffer<T> {
  readonly capacity: number;
  private readonly items: (T | undefined)[];
  private start = 0;
  private count = 0;

  constructor(capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new RangeError(`RingBuffer capacity must be a positive integer, got ${capacity}`);
    }
    this.capacity = capacity;
    this.items = new Array<T | undefined>(capacity);
  }

  get size(): number {
    return this.count;
  }

  get isFull(): boolean {
    return this.count === this.capacity;
  }

  push(item: T): void {
    if (this.count === this.capacity) {
      // Overwrite the oldest slot and advance the read cursor.
      this.items[this.start] = item;
      this.start = (this.start + 1) % this.capacity;
      return;
    }
    const index = (this.start + this.count) % this.capacity;
    this.items[index] = item;
    this.count += 1;
  }

  /** Oldest first. */
  toArray(): T[] {
    const result: T[] = new Array<T>(this.count);
    for (let i = 0; i < this.count; i += 1) {
      result[i] = this.items[(this.start + i) % this.capacity] as T;
    }
    return result;
  }

  /** Newest first. */
  toReversedArray(): T[] {
    const result: T[] = new Array<T>(this.count);
    for (let i = 0; i < this.count; i += 1) {
      result[i] = this.items[(this.start + this.count - 1 - i) % this.capacity] as T;
    }
    return result;
  }

  clear(): void {
    this.items.fill(undefined);
    this.start = 0;
    this.count = 0;
  }

  at(index: number): T | undefined {
    if (index < 0 || index >= this.count) {
      return undefined;
    }
    return this.items[(this.start + index) % this.capacity];
  }
}
