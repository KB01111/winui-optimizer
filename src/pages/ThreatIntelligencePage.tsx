import { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Caption1,
  Dropdown,
  Option,
  DataGrid,
  DataGridBody,
  DataGridCell,
  DataGridHeader,
  DataGridHeaderCell,
  DataGridRow,
  SearchBox,
  Spinner,
  Text,
  createTableColumn,
  makeStyles,
  tokens,
  type TableColumnDefinition,
  type TableRowId,
} from '@fluentui/react-components';
import { ArrowLeftRegular, ArrowRightRegular, ArrowSyncRegular } from '@fluentui/react-icons';
import { getEvent, listEvents, normalizeEventDetail } from '../api/commands';
import type {
  EventFilter,
  SecurityEvent,
  SecurityEventKind,
  SecurityEventDetail,
  Severity,
} from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBanner } from '../components/ErrorBanner';
import { EventDetailPanel } from '../components/EventDetailPanel';
import { SeverityBadge } from '../components/SeverityBadge';
import { Section } from '../components/Section';
import { useAsyncResource } from '../hooks/useAsyncResource';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import { useEventClassification } from '../hooks/useEventClassification';
import { formatNumber, formatScore, formatTimestamp } from '../lib/format';
import { EVENT_KIND_LABELS, EVENT_KIND_ORDER, SEVERITY_ORDER, humanize, kindLabel } from '../lib/severity';
import { useSharedStyles } from '../styles/shared';

const LIMIT_OPTIONS = [50, 100, 200] as const;

const useStyles = makeStyles({
  tableWrapper: {
    overflowX: 'auto',
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
  },
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  search: {
    minWidth: '240px',
    maxWidth: '380px',
    flexGrow: 1,
  },
  pager: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    justifyContent: 'flex-end',
    paddingTop: '8px',
  },
  cellTitle: {
    display: 'block',
    maxWidth: '320px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  cellMono: {
    display: 'block',
    maxWidth: '220px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
  },
  detailScroll: {
    maxHeight: 'calc(100vh - 220px)',
    overflowY: 'auto',
    paddingRight: '4px',
  },
  centered: {
    display: 'flex',
    justifyContent: 'center',
    padding: '24px',
  },
});

const SEVERITY_FILTER_VALUES: Array<Severity | 'all'> = ['all', ...SEVERITY_ORDER];
const KIND_FILTER_VALUES: Array<SecurityEventKind | 'all'> = ['all', ...EVENT_KIND_ORDER];

function MonoCell({ text, title }: { text: string; title?: string }) {
  const styles = useStyles();
  return (
    <Caption1 className={styles.cellMono} title={title}>
      {text}
    </Caption1>
  );
}

function TitleCell({ text }: { text: string }) {
  const styles = useStyles();
  return (
    <Text className={styles.cellTitle} title={text}>
      {text}
    </Text>
  );
}

const columns: TableColumnDefinition<SecurityEvent>[] = [
  createTableColumn<SecurityEvent>({
    columnId: 'time',
    compare: (a, b) => (a.timestampMs ?? 0) - (b.timestampMs ?? 0),
    renderHeaderCell: () => 'Time',
    renderCell: (item) => <MonoCell text={formatTimestamp(item.timestampMs)} />,
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'severity',
    compare: (a, b) => a.severity.localeCompare(b.severity),
    renderHeaderCell: () => 'Severity',
    renderCell: (item) => <SeverityBadge severity={item.severity} />,
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'kind',
    compare: (a, b) => a.kind.localeCompare(b.kind),
    renderHeaderCell: () => 'Kind',
    renderCell: (item) => (
      <Badge appearance="tint" color="subtle" size="small">
        {kindLabel(item.kind)}
      </Badge>
    ),
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'title',
    compare: (a, b) => a.title.localeCompare(b.title),
    renderHeaderCell: () => 'Event',
    renderCell: (item) => <TitleCell text={item.title || kindLabel(item.kind)} />,
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'process',
    renderHeaderCell: () => 'Process',
    renderCell: (item) => <MonoCell text={item.process?.name ?? '—'} title={item.process?.path ?? undefined} />,
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'file',
    renderHeaderCell: () => 'File',
    renderCell: (item) => <MonoCell text={item.file?.name ?? '—'} title={item.file?.path ?? undefined} />,
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'score',
    compare: (a, b) => (a.assessment?.score ?? 0) - (b.assessment?.score ?? 0),
    renderHeaderCell: () => 'Score',
    renderCell: (item) => <Caption1>{formatScore(item.assessment?.score)}</Caption1>,
  }),
  createTableColumn<SecurityEvent>({
    columnId: 'detections',
    renderHeaderCell: () => 'Detections',
    renderCell: (item) => <Caption1>{formatNumber(item.detections.length)}</Caption1>,
  }),
];

export function ThreatIntelligencePage() {
  const styles = useStyles();
  const shared = useSharedStyles();

  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [kind, setKind] = useState<SecurityEventKind | 'all'>('all');
  const [search, setSearch] = useState('');
  const [limit, setLimit] = useState<number>(100);
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const debouncedSearch = useDebouncedValue(search, 300);

  useEffect(() => {
    setOffset(0);
  }, [severity, kind, debouncedSearch, limit]);

  const eventFilter = useMemo<EventFilter>(() => {
    const filter: EventFilter = { limit, offset };
    if (severity !== 'all') {
      filter.severity = severity;
    }
    if (kind !== 'all') {
      filter.kind = kind;
    }
    const trimmed = debouncedSearch.trim();
    if (trimmed.length > 0) {
      filter.search = trimmed;
    }
    return filter;
  }, [limit, offset, severity, kind, debouncedSearch]);

  const page = useAsyncResource(() => listEvents(eventFilter), [eventFilter]);
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
  const classification = useEventClassification(selectedId);

  const items = page.data?.items ?? [];
  const total = page.data?.total ?? 0;
  const nextOffset = page.data?.nextOffset ?? null;
  const rangeStart = total === 0 ? 0 : Math.min(offset + 1, total);
  const rangeEnd = Math.min(offset + items.length, total);

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            Threat intelligence
          </Text>
          <Caption1 className={shared.muted}>
            Stored security events with detections, evidence and policy outcomes
            {page.data ? ` · ${formatNumber(total)} matching event(s)` : ''}
          </Caption1>
        </div>
        <div className={styles.toolbar}>
          <Button
            appearance="secondary"
            icon={<ArrowSyncRegular />}
            onClick={page.reload}
            disabled={page.loading}
          >
            Refresh
          </Button>
        </div>
      </div>

      <div className={styles.toolbar}>
        <SearchBox
          className={styles.search}
          placeholder="Search title, path, process, SHA-256, rule or label"
          value={search}
          onChange={(_, data) => setSearch(data.value)}
        />
        <Dropdown
          placeholder="All severities"
          value={severity === 'all' ? 'All severities' : humanize(severity)}
          selectedOptions={[severity]}
          onOptionSelect={(_, data) => {
            const value = data.optionValue as Severity | 'all';
            setSeverity(value);
          }}
        >
          {SEVERITY_FILTER_VALUES.map((value) => (
            <Option key={value} value={value} text={value === 'all' ? 'All severities' : humanize(value)}>
              {value === 'all' ? 'All severities' : humanize(value)}
            </Option>
          ))}
        </Dropdown>
        <Dropdown
          placeholder="All event kinds"
          value={kind === 'all' ? 'All event kinds' : EVENT_KIND_LABELS[kind]}
          selectedOptions={[kind]}
          onOptionSelect={(_, data) => {
            const value = data.optionValue as SecurityEventKind | 'all';
            setKind(value);
          }}
        >
          {KIND_FILTER_VALUES.map((value) => (
            <Option
              key={value}
              value={value}
              text={value === 'all' ? 'All event kinds' : EVENT_KIND_LABELS[value]}
            >
              {value === 'all' ? 'All event kinds' : EVENT_KIND_LABELS[value]}
            </Option>
          ))}
        </Dropdown>
        <Dropdown
          placeholder="Page size"
          value={`${formatNumber(limit)} per page`}
          selectedOptions={[String(limit)]}
          onOptionSelect={(_, data) => {
            const parsed = Number(data.optionValue);
            if (Number.isFinite(parsed)) {
              setLimit(parsed);
            }
          }}
        >
          {LIMIT_OPTIONS.map((value) => (
            <Option key={value} value={String(value)} text={`${formatNumber(value)} per page`}>
              {`${formatNumber(value)} per page`}
            </Option>
          ))}
        </Dropdown>
      </div>

      {page.error ? (
        <ErrorBanner title="Could not load events" message={page.error} onRetry={page.reload} />
      ) : null}

      <div className={shared.split}>
        <Section
          title="Events"
          subtitle={page.data ? `${formatNumber(rangeStart)}–${formatNumber(rangeEnd)} of ${formatNumber(total)}` : 'Loading…'}
        >
          {page.loading && page.data === null ? (
            <div className={styles.centered}>
              <Spinner label="Loading events…" />
            </div>
          ) : null}
          {!page.loading && !page.error && items.length === 0 ? (
            <EmptyState
              title="No events match the filters"
              description="Nothing in the event store matches this severity/kind/search combination."
            />
          ) : null}
          {items.length > 0 ? (
            <div className={styles.tableWrapper}>
              <DataGrid
                items={items}
                columns={columns}
                getRowId={(item) => item.id}
                selectionMode="single"
                selectedItems={selectedId ? [selectedId as TableRowId] : []}
                onSelectionChange={(_, data) => {
                  const first = Array.from(data.selectedItems)[0];
                  setSelectedId(first === undefined ? null : String(first));
                }}
                sortable
                focusMode="composite"
              >
                <DataGridHeader>
                  <DataGridRow>
                    {({ renderHeaderCell }) => (
                      <DataGridHeaderCell>{renderHeaderCell()}</DataGridHeaderCell>
                    )}
                  </DataGridRow>
                </DataGridHeader>
                <DataGridBody<SecurityEvent>>
                  {({ item, rowId }) => (
                    <DataGridRow<SecurityEvent> key={rowId}>
                      {({ renderCell }) => <DataGridCell>{renderCell(item)}</DataGridCell>}
                    </DataGridRow>
                  )}
                </DataGridBody>
              </DataGrid>
            </div>
          ) : null}
          <div className={styles.pager}>
            <Caption1>
              {page.data
                ? `Page starting at ${formatNumber(offset + (items.length === 0 ? 0 : 1))}`
                : '—'}
            </Caption1>
            <Button
              appearance="secondary"
              icon={<ArrowLeftRegular />}
              disabled={offset === 0 || page.loading}
              onClick={() => setOffset(Math.max(0, offset - limit))}
            >
              Previous
            </Button>
            <Button
              appearance="secondary"
              icon={<ArrowRightRegular />}
              iconPosition="after"
              disabled={nextOffset === null || page.loading}
              onClick={() => {
                if (nextOffset !== null) {
                  setOffset(nextOffset);
                }
              }}
            >
              Next
            </Button>
          </div>
        </Section>

        <Section title="Event detail" subtitle="Selection from the table">
          <div className={styles.detailScroll}>
            <EventDetailPanel
              detail={detail.data}
              loading={detail.loading && selectedId !== null}
              error={detail.error}
              onClassify={() => void classification.run()}
              classifying={classification.classifying}
              classifyError={classification.error}
              classifyResult={classification.result}
              emptyTitle="No event selected"
              emptyDescription="Select a row to inspect hashes, YARA matches, process ancestry, evidence timeline and policy outcome."
            />
          </div>
        </Section>
      </div>
    </div>
  );
}
