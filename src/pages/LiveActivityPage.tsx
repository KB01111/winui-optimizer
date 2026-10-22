import { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Caption1,
  DrawerBody,
  DrawerHeader,
  DrawerHeaderTitle,
  Dropdown,
  MessageBar,
  MessageBarBody,
  Option,
  OverlayDrawer,
  SearchBox,
  Switch,
  Text,
  ToggleButton,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import {
  ArrowSyncRegular,
  DeleteRegular,
  PauseRegular,
  PlayRegular,
} from '@fluentui/react-icons';
import { getEvent, normalizeEventDetail } from '../api/commands';
import type { SecurityEventDetail, SecurityEventKind, Severity } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBanner } from '../components/ErrorBanner';
import { EventDetailPanel } from '../components/EventDetailPanel';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusPill } from '../components/StatusPill';
import { useAsyncResource } from '../hooks/useAsyncResource';
import { useEventClassification } from '../hooks/useEventClassification';
import { useNow } from '../hooks/useNow';
import { useVirtualList } from '../hooks/useVirtualList';
import { countBySeverity, filterEvents } from '../lib/filters';
import { formatNumber, formatRelative, formatTimestamp } from '../lib/format';
import {
  EVENT_KIND_LABELS,
  EVENT_KIND_ORDER,
  SEVERITY_ORDER,
  humanize,
  kindLabel,
} from '../lib/severity';
import { useLiveEvents } from '../state/LiveEventsProvider';
import { useSharedStyles } from '../styles/shared';

const ROW_HEIGHT = 44;

const useStyles = makeStyles({
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  grow: {
    flexGrow: 1,
    minWidth: '200px',
    maxWidth: '360px',
  },
  scroll: {
    overflowY: 'auto',
    height: 'calc(100vh - 320px)',
    minHeight: '280px',
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground1,
    position: 'relative',
  },
  canvas: {
    position: 'relative',
    width: '100%',
  },
  row: {
    position: 'absolute',
    left: 0,
    right: 0,
    display: 'grid',
    gridTemplateColumns: '84px auto auto minmax(0, 1fr)',
    alignItems: 'center',
    gap: '8px',
    padding: '0 12px',
    border: 'none',
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
    backgroundColor: tokens.colorNeutralBackground1,
    color: tokens.colorNeutralForeground1,
    textAlign: 'left',
    cursor: 'pointer',
    boxSizing: 'border-box',
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
    ':focus-visible': {
      outline: `2px solid ${tokens.colorStrokeFocus2}`,
      outlineOffset: '-2px',
    },
  },
  rowTime: {
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground3,
    whiteSpace: 'nowrap',
  },
  rowTitle: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  rowMeta: {
    display: 'flex',
    gap: '8px',
    overflow: 'hidden',
    color: tokens.colorNeutralForeground3,
    whiteSpace: 'nowrap',
  },
  header: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  counters: {
    display: 'flex',
    gap: '4px',
    flexWrap: 'wrap',
  },
});

const SEVERITY_OPTIONS: Severity[] = [...SEVERITY_ORDER];
const KIND_OPTIONS: SecurityEventKind[] = [...EVENT_KIND_ORDER];

export function LiveActivityPage() {
  const styles = useStyles();
  const shared = useSharedStyles();
  const {
    events,
    bufferedEvents,
    capacity,
    paused,
    setPaused,
    connectionError,
    lastEventAtMs,
    clear,
  } = useLiveEvents();

  const [search, setSearch] = useState('');
  const [severities, setSeverities] = useState<Severity[]>([]);
  const [kinds, setKinds] = useState<SecurityEventKind[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const classification = useEventClassification(selectedId);
  const now = useNow(10_000);

  const filter = useMemo(() => ({ severities, kinds, search, minSeverity: null }), [severities, kinds, search]);
  const filtered = useMemo(() => filterEvents(events, filter), [events, filter]);
  const severityCounts = useMemo(() => countBySeverity(bufferedEvents), [bufferedEvents]);

  const virtual = useVirtualList({ itemCount: filtered.length, itemHeight: ROW_HEIGHT, overscan: 8 });
  const { resetScroll, scrollRef, onScroll, items: virtualItems, totalHeight } = virtual;

  const detail = useAsyncResource<SecurityEventDetail | null>(
    async () => {
      if (!selectedId) {
        return null;
      }
      const raw = await getEvent(selectedId);
      return normalizeEventDetail(raw);
    },
    [selectedId],
  );

  // Newest-first feed: when auto-scroll is on, keep the newest row in view.
  const newestId = filtered.length > 0 ? filtered[0]?.id ?? null : null;
  useEffect(() => {
    if (!autoScroll || paused) {
      return;
    }
    resetScroll();
  }, [newestId, autoScroll, paused, resetScroll]);

  useEffect(() => {
    resetScroll();
  }, [severities, kinds, search, resetScroll]);

  const kindValue =
    kinds.length === 0 ? '' : kinds.map((kind) => EVENT_KIND_LABELS[kind] ?? kind).join(', ');
  const severityValue = severities.length === 0 ? '' : severities.map(humanize).join(', ');

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            Live activity
          </Text>
          <Caption1 className={shared.muted}>
            Bounded to the newest {formatNumber(capacity)} events · {formatNumber(bufferedEvents.length)} buffered
            {lastEventAtMs !== null ? ` · last event ${formatRelative(lastEventAtMs, now)}` : ''}
          </Caption1>
        </div>
        <div className={styles.toolbar}>
          <StatusPill label={connectionError ? 'Not connected' : 'Live'} tone={connectionError ? 'danger' : 'success'} />
          <ToggleButton
            appearance="secondary"
            checked={paused}
            icon={paused ? <PlayRegular /> : <PauseRegular />}
            onClick={() => setPaused(!paused)}
          >
            {paused ? 'Resume' : 'Pause'}
          </ToggleButton>
          <Switch
            label="Auto-scroll"
            checked={autoScroll}
            onChange={(_, data) => setAutoScroll(data.checked)}
          />
          <Button
            appearance="secondary"
            icon={<DeleteRegular />}
            onClick={clear}
            disabled={bufferedEvents.length === 0}
          >
            Clear
          </Button>
        </div>
      </div>

      {connectionError ? (
        <ErrorBanner title="Live feed unavailable" message={connectionError} />
      ) : null}

      {paused ? (
        <MessageBar intent="info">
          <MessageBarBody>
            Feed paused. New events keep arriving and are buffered
            {bufferedEvents.length > events.length
              ? ` (${formatNumber(bufferedEvents.length - events.length)} newer than the frozen view).`
              : '.'}
          </MessageBarBody>
        </MessageBar>
      ) : null}

      <div className={styles.toolbar}>
        <SearchBox
          className={styles.grow}
          placeholder="Search title, path, process, rule or label"
          value={search}
          onChange={(_, data) => setSearch(data.value)}
        />
        <Dropdown
          multiselect
          placeholder="All severities"
          selectedOptions={severities}
          value={severityValue}
          onOptionSelect={(_, data) =>
            setSeverities(data.selectedOptions.filter((option): option is Severity =>
              (SEVERITY_OPTIONS as string[]).includes(option),
            ))
          }
        >
          {SEVERITY_OPTIONS.map((severity) => (
            <Option key={severity} value={severity} text={humanize(severity)}>
              {humanize(severity)}
            </Option>
          ))}
        </Dropdown>
        <Dropdown
          multiselect
          placeholder="All event kinds"
          selectedOptions={kinds}
          value={kindValue}
          onOptionSelect={(_, data) =>
            setKinds(
              data.selectedOptions.filter((option): option is SecurityEventKind =>
                (KIND_OPTIONS as string[]).includes(option),
              ),
            )
          }
        >
          {KIND_OPTIONS.map((kind) => (
            <Option key={kind} value={kind} text={EVENT_KIND_LABELS[kind]}>
              {EVENT_KIND_LABELS[kind]}
            </Option>
          ))}
        </Dropdown>
        <div className={styles.counters}>
          {SEVERITY_OPTIONS.map((severity) => (
            <SeverityBadge key={severity} severity={severity} count={severityCounts[severity]} />
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          title={bufferedEvents.length === 0 ? 'No events yet' : 'No events match the current filters'}
          description={
            bufferedEvents.length === 0
              ? 'The engine has not emitted any events for this session. Start monitoring from the Overview page or run a scan.'
              : 'Adjust the severity, kind or search filters to widen the view.'
          }
          icon={<ArrowSyncRegular />}
        />
      ) : (
        <div ref={scrollRef} className={styles.scroll} onScroll={onScroll} role="list" aria-label="Live event feed">
          <div className={styles.canvas} style={{ height: totalHeight }}>
            {virtualItems.map((item) => {
              const event = filtered[item.index];
              if (!event) {
                return null;
              }
              return (
                <button
                  type="button"
                  role="listitem"
                  key={event.id}
                  className={styles.row}
                  style={{ top: item.offsetTop, height: ROW_HEIGHT }}
                  onClick={() => setSelectedId(event.id)}
                  title={event.title || kindLabel(event.kind)}
                >
                  <Caption1 className={styles.rowTime}>{formatTimestamp(event.timestampMs)}</Caption1>
                  <SeverityBadge severity={event.severity} />
                  <Badge appearance="tint" color="subtle" size="small">
                    {kindLabel(event.kind)}
                  </Badge>
                  <span className={styles.rowMeta}>
                    <Text size={200} className={styles.rowTitle}>
                      {event.title || kindLabel(event.kind)}
                    </Text>
                    {event.process?.name ? <Caption1>{event.process.name}</Caption1> : null}
                    {event.file?.path ? <Caption1>{event.file.path}</Caption1> : null}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <OverlayDrawer
        open={selectedId !== null}
        onOpenChange={(_, data) => {
          if (!data.open) {
            setSelectedId(null);
          }
        }}
        position="end"
        size="medium"
      >
        <DrawerHeader>
          <DrawerHeaderTitle>Event detail</DrawerHeaderTitle>
        </DrawerHeader>
        <DrawerBody>
          <div className={styles.header}>
            <EventDetailPanel
              detail={detail.data}
              loading={detail.loading && selectedId !== null}
              error={detail.error}
              onClassify={() => void classification.run()}
              classifying={classification.classifying}
              classifyError={classification.error}
              classifyResult={classification.result}
            />
          </div>
        </DrawerBody>
      </OverlayDrawer>
    </div>
  );
}
