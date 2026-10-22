import { describe, expect, it } from 'vitest';
import { RingBuffer } from '../../src/state/ringBuffer';

describe('RingBuffer', () => {
  it('keeps insertion order until full', () => {
    const buffer = new RingBuffer<number>(3);
    buffer.push(1);
    buffer.push(2);
    buffer.push(3);
    expect(buffer.size).toBe(3);
    expect(buffer.isFull).toBe(true);
    expect(buffer.toArray()).toEqual([1, 2, 3]);
  });

  it('drops the oldest entry when capacity is exceeded', () => {
    const buffer = new RingBuffer<number>(3);
    for (const value of [1, 2, 3, 4, 5]) {
      buffer.push(value);
    }
    expect(buffer.size).toBe(3);
    expect(buffer.toArray()).toEqual([3, 4, 5]);
    expect(buffer.toReversedArray()).toEqual([5, 4, 3]);
    expect(buffer.at(0)).toBe(3);
    expect(buffer.at(2)).toBe(5);
    expect(buffer.at(3)).toBeUndefined();
  });

  it('clears all entries', () => {
    const buffer = new RingBuffer<string>(2);
    buffer.push('a');
    buffer.push('b');
    buffer.clear();
    expect(buffer.size).toBe(0);
    expect(buffer.toArray()).toEqual([]);
  });

  it('rejects invalid capacities', () => {
    expect(() => new RingBuffer<number>(0)).toThrow(RangeError);
    expect(() => new RingBuffer<number>(1.5)).toThrow(RangeError);
  });
});
