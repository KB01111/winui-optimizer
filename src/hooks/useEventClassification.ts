import { useCallback, useEffect, useRef, useState } from 'react';
import { classifyEvent } from '../api/commands';
import type { DecisionResult } from '../api/types';
import { describeError } from '../lib/errors';

export interface EventClassificationState {
  result: DecisionResult | null;
  error: string | null;
  classifying: boolean;
  run: () => Promise<void>;
}

const NO_DECISION_NOTICE =
  'The AI router returned no decision. This is expected when AI is in offline mode or when deterministic policy skipped classification.';

/** `classify_event` state machine that never leaks results across events. */
export function useEventClassification(eventId: string | null): EventClassificationState {
  const [result, setResult] = useState<DecisionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [classifying, setClassifying] = useState(false);
  const requestRef = useRef(0);

  useEffect(() => {
    requestRef.current += 1;
    setResult(null);
    setError(null);
    setClassifying(false);
  }, [eventId]);

  const run = useCallback(async () => {
    if (!eventId) {
      return;
    }
    const requestId = requestRef.current + 1;
    requestRef.current = requestId;
    setClassifying(true);
    setError(null);
    try {
      const decision = await classifyEvent(eventId);
      if (requestRef.current !== requestId) {
        return;
      }
      if (decision === null) {
        setResult(null);
        setError(NO_DECISION_NOTICE);
      } else {
        setResult(decision);
      }
    } catch (classificationError) {
      if (requestRef.current === requestId) {
        setError(describeError(classificationError));
      }
    } finally {
      if (requestRef.current === requestId) {
        setClassifying(false);
      }
    }
  }, [eventId]);

  return { result, error, classifying, run };
}
