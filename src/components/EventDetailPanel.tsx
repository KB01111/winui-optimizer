import { useCallback, useState, type ReactNode } from 'react';
import {
  Badge,
  Button,
  Caption1,
  Divider,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
  ProgressBar,
  Spinner,
  Text,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import { LockClosedRegular } from '@fluentui/react-icons';
import type {
  DecisionResult,
  PolicyDecision,
  SecurityEvent,
  SecurityEventDetail,
} from '../api/types';
import { EmptyState } from './EmptyState';
import { KeyValue } from './KeyValue';
import { Section } from './Section';
import { SeverityBadge } from './SeverityBadge';
import { extractAncestry, stringifyEvidence } from '../lib/evidence';
import { describeError } from '../lib/errors';
import {
  DECISION_CATEGORY_LABELS,
  DETECTION_SOURCE_LABELS,
  POLICY_OUTCOME_LABELS,
  TELEMETRY_SOURCE_LABELS,
  decisionCategoryTone,
  humanize,
  kindLabel,
  policyOutcomeTone,
  riskTone,
} from '../lib/severity';
import { formatNumber, formatProbability, formatScore, formatTimestamp, formatUsd } from '../lib/format';
import { useOptionalQuarantine } from '../state/QuarantineProvider';

const useStyles = makeStyles({
  root: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    minWidth: 0,
  },
  header: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  headerMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  probabilities: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  probabilityRow: {
    display: 'grid',
    gridTemplateColumns: 'minmax(120px, 180px) 1fr 64px',
    alignItems: 'center',
    gap: '8px',
  },
  probabilityLabel: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  probabilityValue: {
    textAlign: 'right',
    fontFamily: tokens.fontFamilyMonospace,
  },
  flagRow: {
    display: 'flex',
    gap: '4px',
    flexWrap: 'wrap',
  },
  reasons: {
    margin: 0,
    paddingLeft: '18px',
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  timeline: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    borderLeft: `2px solid ${tokens.colorNeutralStroke2}`,
    paddingLeft: '12px',
  },
  timelineRow: {
    display: 'flex',
    gap: '8px',
    alignItems: 'baseline',
  },
  timelineTime: {
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground3,
    whiteSpace: 'nowrap',
  },
  mono: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    overflowWrap: 'anywhere',
  },
  pre: {
    margin: 0,
    padding: '8px',
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground2,
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    maxHeight: '240px',
    overflow: 'auto',
    whiteSpace: 'pre-wrap',
  },
  muted: {
    color: tokens.colorNeutralForeground3,
  },
  decisionCard: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    padding: '12px',
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground2,
    minWidth: 0,
  },
  centered: {
    display: 'flex',
    justifyContent: 'center',
    padding: '24px',
  },
  quarantineBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    alignItems: 'flex-start',
  },
});

export interface EventDetailPanelProps {
  detail: SecurityEventDetail | null;
  loading?: boolean;
  error?: string | null;
  onClassify?: () => void;
  classifying?: boolean;
  classifyError?: string | null;
  classifyResult?: DecisionResult | null;
  emptyTitle?: string;
  emptyDescription?: string;
  /**
   * Quarantine handler. When omitted the shared quarantine provider is used;
   * when no provider is mounted the button is not rendered at all.
   */
  onQuarantine?: (path: string, reason: string) => Promise<void>;
}

function ProbabilityList({ probabilities }: { probabilities: Record<string, number> }) {
  const styles = useStyles();
  const entries = Object.entries(probabilities ?? {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return <Caption1 className={styles.muted}>The provider did not report a probability breakdown.</Caption1>;
  }
  return (
    <div className={styles.probabilities}>
      {entries.map(([key, value]) => (
        <div key={key} className={styles.probabilityRow}>
          <Caption1 className={styles.probabilityLabel} title={key}>
            {humanize(key)}
          </Caption1>
          <ProgressBar value={Math.min(1, Math.max(0, value))} thickness="medium" />
          <Caption1 className={styles.probabilityValue}>{formatProbability(value)}</Caption1>
        </div>
      ))}
    </div>
  );
}

function FlagRow({ decision }: { decision: DecisionResult }) {
  const styles = useStyles();
  const flags: Array<{ active: boolean; label: string }> = [
    { active: decision.requiresInvestigation, label: 'Requires investigation' },
    { active: decision.suspiciousPersistence, label: 'Suspicious persistence' },
    { active: decision.credentialTheft, label: 'Credential theft' },
    { active: decision.ransomware, label: 'Ransomware' },
  ];
  const activeFlags = flags.filter((flag) => flag.active);
  if (activeFlags.length === 0) {
    return <Caption1 className={styles.muted}>The provider flagged none of the tracked behaviours.</Caption1>;
  }
  return (
    <div className={styles.flagRow}>
      {activeFlags.map((flag) => (
        <Badge key={flag.label} appearance="tint" color="important" size="small">
          {flag.label}
        </Badge>
      ))}
    </div>
  );
}

function DecisionCard({ decision, title }: { decision: DecisionResult; title: string }) {
  const styles = useStyles();
  return (
    <div className={styles.decisionCard}>
      <div className={styles.headerMeta}>
        <Text weight="semibold">{title}</Text>
        <Badge appearance="tint" color={decisionCategoryTone(decision.category)} size="small">
          {DECISION_CATEGORY_LABELS[decision.category] ?? humanize(decision.category)}
        </Badge>
        {decision.escalated ? (
          <Badge appearance="tint" color="informative" size="small">
            Escalated
          </Badge>
        ) : null}
      </div>
      <KeyValue label="Provider" value={decision.provider} />
      <KeyValue label="Model" value={decision.modelVersion ? `${decision.model} (${decision.modelVersion})` : decision.model} />
      <KeyValue label="Confidence" value={`${formatProbability(decision.confidence)} (reported, uncalibrated)`} />
      <KeyValue label="Latency" value={decision.latencyMs !== undefined ? `${formatNumber(decision.latencyMs)} ms` : '—'} />
      <KeyValue label="Cost" value={formatUsd(decision.costUsd)} />
      <KeyValue label="Evaluated at" value={formatTimestamp(decision.timestampMs)} />
      <FlagRow decision={decision} />
      <div>
        <Caption1 className={styles.muted}>Reported probabilities (uncalibrated)</Caption1>
        <ProbabilityList probabilities={decision.probabilities} />
      </div>
      {decision.evidence.length > 0 ? (
        <div>
          <Caption1 className={styles.muted}>Provider evidence</Caption1>
          <ul className={styles.reasons}>
            {decision.evidence.map((item, index) => (
              <li key={`${index}-${item}`}>{item}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function PolicyDecisionCard({ decision }: { decision: PolicyDecision }) {
  const styles = useStyles();
  return (
    <div className={styles.decisionCard}>
      <div className={styles.headerMeta}>
        <Badge appearance="tint" color={policyOutcomeTone(decision.outcome)} size="small">
          {POLICY_OUTCOME_LABELS[decision.outcome] ?? humanize(decision.outcome)}
        </Badge>
        {decision.deterministic ? (
          <Badge appearance="tint" color="success" size="small">
            Deterministic
          </Badge>
        ) : null}
        {decision.requiresHumanApproval ? (
          <Badge appearance="tint" color="warning" size="small">
            Human approval required
          </Badge>
        ) : null}
        {decision.quarantineAllowed ? (
          <Badge appearance="tint" color="important" size="small">
            Quarantine allowed
          </Badge>
        ) : null}
      </div>
      <Text>{decision.reason}</Text>
      <KeyValue label="Matched rules" value={decision.matchedRules.join(', ')} mono />
      <KeyValue label="Decided at" value={formatTimestamp(decision.createdAtMs)} />
    </div>
  );
}

interface TimelineEntry {
  ms: number;
  label: string;
  severity?: SecurityEvent['severity'];
}

function buildTimeline(event: SecurityEvent, related: SecurityEvent[]): TimelineEntry[] {
  const entries: TimelineEntry[] = [];
  entries.push({ ms: event.timestampMs, label: `Event observed — ${kindLabel(event.kind)}`, severity: event.severity });
  for (const detection of event.detections ?? []) {
    entries.push({
      ms: detection.createdAtMs,
      label: `Detection ${detection.ruleId} — ${detection.ruleName}`,
      severity: detection.severity,
    });
  }
  for (const other of related ?? []) {
    if (other.id !== event.id) {
      entries.push({ ms: other.timestampMs, label: `Related event — ${other.title || kindLabel(other.kind)}`, severity: other.severity });
    }
  }
  return entries
    .filter((entry) => typeof entry.ms === 'number' && entry.ms > 0)
    .sort((a, b) => a.ms - b.ms);
}

/**
 * Manual quarantine action for a single file. The backend copies the file into
 * the local vault; the original file is never deleted by this action.
 */
function QuarantineAction({
  path,
  reason,
  onQuarantine,
}: {
  path: string;
  reason: string;
  onQuarantine: (path: string, reason: string) => Promise<void>;
}) {
  const styles = useStyles();
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ intent: 'success' | 'error'; message: string } | null>(null);

  const onClick = useCallback(async () => {
    setBusy(true);
    setFeedback(null);
    try {
      await onQuarantine(path, reason);
      setFeedback({
        intent: 'success',
        message: 'A copy was stored in the local quarantine vault. The original file was left in place.',
      });
    } catch (quarantineError) {
      setFeedback({ intent: 'error', message: describeError(quarantineError) });
    } finally {
      setBusy(false);
    }
  }, [onQuarantine, path, reason]);

  return (
    <div className={styles.quarantineBlock}>
      <Button appearance="secondary" icon={<LockClosedRegular />} disabled={busy} onClick={() => void onClick()}>
        {busy ? 'Quarantining…' : 'Quarantine file'}
      </Button>
      {feedback ? (
        <MessageBar intent={feedback.intent}>
          <MessageBarBody>{feedback.message}</MessageBarBody>
        </MessageBar>
      ) : null}
    </div>
  );
}

/** Shared detail renderer for the feed click-through and the threat table. */
export function EventDetailPanel({
  detail,
  loading = false,
  error = null,
  onClassify,
  classifying = false,
  classifyError = null,
  classifyResult = null,
  emptyTitle = 'No event selected',
  emptyDescription = 'Pick an event to see hashes, detections, evidence and policy outcome.',
  onQuarantine,
}: EventDetailPanelProps) {
  const styles = useStyles();
  const quarantineContext = useOptionalQuarantine();

  const quarantineViaProvider = useCallback(
    async (path: string, reason: string) => {
      if (quarantineContext) {
        await quarantineContext.quarantine(path, reason);
      }
    },
    [quarantineContext],
  );

  const quarantineHandler = onQuarantine ?? (quarantineContext ? quarantineViaProvider : undefined);

  if (loading) {
    return (
      <div className={styles.centered}>
        <Spinner label="Loading event detail…" />
      </div>
    );
  }

  if (error) {
    return (
      <MessageBar intent="error">
        <MessageBarBody>
          <MessageBarTitle>Could not load event detail</MessageBarTitle>
          {error}
        </MessageBarBody>
      </MessageBar>
    );
  }

  if (!detail) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />;
  }

  const { event, decisions = [], policy = null, related = [] } = detail;
  const yaraDetections = (event.detections ?? []).filter((detection) => detection.source === 'yara');
  const ancestry = extractAncestry(event.evidence);
  const timeline = buildTimeline(event, related);
  const aiDecisions = classifyResult ? [classifyResult, ...decisions] : decisions;
  const evidenceText = stringifyEvidence(event.evidence);

  const decisionNode = (decision: DecisionResult, index: number): ReactNode => (
    <DecisionCard
      key={decision.id || `decision-${index}`}
      decision={decision}
      title={index === 0 && classifyResult ? 'Latest classification' : 'Classification result'}
    />
  );

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <Text size={500} weight="semibold">
          {event.title || kindLabel(event.kind)}
        </Text>
        <div className={styles.headerMeta}>
          <SeverityBadge severity={event.severity} />
          <Badge appearance="tint" color="subtle" size="small">
            {kindLabel(event.kind)}
          </Badge>
          <Badge appearance="tint" color="subtle" size="small">
            {TELEMETRY_SOURCE_LABELS[event.source] ?? humanize(event.source)}
          </Badge>
          {event.correlationId ? (
            <Badge appearance="tint" color="informative" size="small">
              Correlated
            </Badge>
          ) : null}
        </div>
        {event.description ? <Text>{event.description}</Text> : null}
      </div>

      <KeyValue label="Event id" value={event.id} mono />
      <KeyValue label="Observed at" value={formatTimestamp(event.timestampMs)} />
      {event.correlationId ? <KeyValue label="Correlation id" value={event.correlationId} mono /> : null}
      {event.labels.length > 0 ? <KeyValue label="Labels" value={event.labels.join(', ')} /> : null}

      <Divider />

      <Section title="Assessment" subtitle="Deterministic score computed by the Rust engine">
        {event.assessment ? (
          <>
            <div className={styles.headerMeta}>
              <Badge appearance="tint" color={riskTone(event.assessment.level)} size="medium">
                {`${event.assessment.level.toUpperCase()} · ${formatScore(event.assessment.score)}/100`}
              </Badge>
              <Badge appearance="tint" color={event.assessment.deterministic ? 'success' : 'warning'} size="small">
                {event.assessment.deterministic ? 'Deterministic only' : 'Includes non-deterministic input'}
              </Badge>
            </div>
            {event.assessment.reasons.length > 0 ? (
              <ul className={styles.reasons}>
                {event.assessment.reasons.map((reason, index) => (
                  <li key={`${index}-${reason}`}>{reason}</li>
                ))}
              </ul>
            ) : (
              <Caption1 className={styles.muted}>No risk signals were active for this event.</Caption1>
            )}
          </>
        ) : (
          <Caption1 className={styles.muted}>No risk assessment was recorded for this event.</Caption1>
        )}
      </Section>

      <Section title="Detections" subtitle={`${event.detections.length} deterministic detection(s)`}>
        {event.detections.length === 0 ? (
          <Caption1 className={styles.muted}>No deterministic detections were produced.</Caption1>
        ) : (
          event.detections.map((detection) => (
            <div key={detection.id} className={styles.decisionCard}>
              <div className={styles.headerMeta}>
                <SeverityBadge severity={detection.severity} />
                <Badge appearance="tint" color="informative" size="small">
                  {DETECTION_SOURCE_LABELS[detection.source] ?? humanize(detection.source)}
                </Badge>
                <Caption1 className={styles.muted}>{detection.ruleId}</Caption1>
              </div>
              <Text>{detection.ruleName}</Text>
              <Caption1>{detection.description}</Caption1>
              <KeyValue label="Score contribution" value={formatScore(detection.scoreContribution)} />
              {detection.evidence.length > 0 ? (
                <ul className={styles.reasons}>
                  {detection.evidence.map((item, index) => (
                    <li key={`${index}-${item}`}>{item}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ))
        )}
      </Section>

      <Section title="Hashes and file" subtitle="Identifiers recorded for this event">
        <KeyValue label="File path" value={event.file?.path} mono />
        <KeyValue label="File name" value={event.file?.name} />
        <KeyValue label="File SHA-256" value={event.file?.sha256} mono />
        <KeyValue label="Process" value={event.process?.name} />
        <KeyValue label="Process path" value={event.process?.path} mono />
        <KeyValue label="Process SHA-256" value={event.process?.sha256} mono />
        <KeyValue label="Process user" value={event.process?.user} />
        <KeyValue label="Process signed" value={event.process?.signed === null || event.process?.signed === undefined ? undefined : event.process.signed ? 'Signed' : 'Unsigned'} />
        <KeyValue label="Signer" value={event.process?.signer} />
        {quarantineHandler && event.file?.path && event.detections.length > 0 ? (
          <QuarantineAction
            path={event.file.path}
            reason={`Manual quarantine from ${kindLabel(event.kind)} event: ${event.detections
              .map((detection) => detection.ruleId || detection.source)
              .join(', ')}`}
            onQuarantine={quarantineHandler}
          />
        ) : null}
      </Section>

      <Section title="YARA matches" subtitle="Rule matches from the deterministic scanner">
        {yaraDetections.length === 0 ? (
          <Caption1 className={styles.muted}>No YARA rule matched this event.</Caption1>
        ) : (
          yaraDetections.map((detection) => (
            <div key={detection.id} className={styles.decisionCard}>
              <div className={styles.headerMeta}>
                <SeverityBadge severity={detection.severity} />
                <Caption1 className={styles.muted}>{detection.ruleId}</Caption1>
              </div>
              <Text>{detection.ruleName}</Text>
              {detection.evidence.length > 0 ? (
                <ul className={styles.reasons}>
                  {detection.evidence.map((item, index) => (
                    <li key={`${index}-${item}`}>{item}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ))
        )}
      </Section>

      <Section title="Process ancestry" subtitle="Read from the event evidence payload">
        {ancestry.length === 0 ? (
          <Caption1 className={styles.muted}>
            No process ancestry is recorded in this event's evidence.
          </Caption1>
        ) : (
          <ol className={styles.reasons}>
            {ancestry.map((entry, index) => (
              <li key={`${entry.pid ?? 'pid'}-${index}`}>
                <span className={styles.mono}>
                  {entry.pid !== null ? `[${entry.pid}] ` : ''}
                  {entry.name}
                </span>
                {entry.path ? <Caption1 className={styles.muted}>{` — ${entry.path}`}</Caption1> : null}
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Section title="Evidence timeline" subtitle="Observation and detection timestamps, oldest first">
        {timeline.length === 0 ? (
          <Caption1 className={styles.muted}>No timestamps are available for this event.</Caption1>
        ) : (
          <div className={styles.timeline}>
            {timeline.map((entry, index) => (
              <div key={`${entry.ms}-${index}`} className={styles.timelineRow}>
                <Caption1 className={styles.timelineTime}>{formatTimestamp(entry.ms)}</Caption1>
                {entry.severity ? <SeverityBadge severity={entry.severity} /> : null}
                <Caption1>{entry.label}</Caption1>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section
        title="AI classification"
        subtitle="Advisory only — the deterministic policy engine decides outcomes"
        action={
          onClassify ? (
            <Button appearance="secondary" onClick={onClassify} disabled={classifying}>
              {classifying ? 'Classifying…' : 'Run AI classification'}
            </Button>
          ) : undefined
        }
      >
        <MessageBar intent="warning">
          <MessageBarBody>
            <MessageBarTitle>Probabilities are uncalibrated</MessageBarTitle>
            Values are reported verbatim by the decision provider. They are not statistical confidence
            bounds, and AI output can never trigger quarantine or any destructive action.
          </MessageBarBody>
        </MessageBar>
        {classifyError ? (
          <MessageBar intent="error">
            <MessageBarBody>
              <MessageBarTitle>Classification failed</MessageBarTitle>
              {classifyError}
            </MessageBarBody>
          </MessageBar>
        ) : null}
        {aiDecisions.length === 0 ? (
          <Caption1 className={styles.muted}>
            No AI decision was recorded for this event. The engine stays fully functional without a provider.
          </Caption1>
        ) : (
          aiDecisions.map(decisionNode)
        )}
      </Section>

      <Section title="Policy decision" subtitle="Deterministic outcome and audit trail">
        {policy === null ? (
          <Caption1 className={styles.muted}>
            No policy decision is stored for this event yet.
          </Caption1>
        ) : (
          <PolicyDecisionCard decision={policy} />
        )}
      </Section>

      {evidenceText ? (
        <Section title="Raw evidence" subtitle="Structured, bounded evidence as stored (no file contents)">
          <pre className={styles.pre}>{evidenceText}</pre>
        </Section>
      ) : null}
    </div>
  );
}
