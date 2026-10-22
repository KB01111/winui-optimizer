import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from 'react';

export interface UseVirtualListOptions {
  itemCount: number;
  /** Fixed row height in px; rows must render at exactly this height. */
  itemHeight: number;
  overscan?: number;
}

export interface VirtualItem {
  index: number;
  offsetTop: number;
}

export interface UseVirtualListResult {
  scrollRef: RefObject<HTMLDivElement | null>;
  onScroll: () => void;
  resetScroll: () => void;
  totalHeight: number;
  items: VirtualItem[];
  viewportHeight: number;
}

/**
 * Minimal fixed-height windowing for the live event feed. Chosen over a
 * dependency because the viewport is a plain scroll container and rows have a
 * known height, which keeps re-renders cheap under high event volume.
 */
export function useVirtualList(options: UseVirtualListOptions): UseVirtualListResult {
  const { itemCount, itemHeight, overscan = 6 } = options;
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);

  const onScroll = useCallback(() => {
    const element = scrollRef.current;
    if (element) {
      setScrollTop(element.scrollTop);
    }
  }, []);

  const resetScroll = useCallback(() => {
    const element = scrollRef.current;
    if (element) {
      element.scrollTop = 0;
    }
    setScrollTop(0);
  }, []);

  useEffect(() => {
    const element = scrollRef.current;
    if (!element) {
      return;
    }
    const measure = () => {
      setViewportHeight(element.clientHeight);
    };
    measure();
    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(measure);
      observer.observe(element);
      return () => {
        observer.disconnect();
      };
    }
    window.addEventListener('resize', measure);
    return () => {
      window.removeEventListener('resize', measure);
    };
  }, []);

  const items = useMemo(() => {
    if (itemCount <= 0 || itemHeight <= 0) {
      return [];
    }
    const height = viewportHeight > 0 ? viewportHeight : 480;
    const first = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const visibleCount = Math.ceil(height / itemHeight) + overscan * 2;
    const last = Math.min(itemCount, first + visibleCount);
    const result: VirtualItem[] = [];
    for (let index = first; index < last; index += 1) {
      result.push({ index, offsetTop: index * itemHeight });
    }
    return result;
  }, [itemCount, itemHeight, overscan, scrollTop, viewportHeight]);

  return {
    scrollRef,
    onScroll,
    resetScroll,
    totalHeight: Math.max(0, itemCount) * itemHeight,
    items,
    viewportHeight,
  };
}
