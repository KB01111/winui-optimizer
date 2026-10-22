import { useCallback, useMemo, useState, type ReactNode } from 'react';
import {
  Badge,
  Button,
  Caption1,
  DrawerBody,
  DrawerHeader,
  DrawerHeaderTitle,
  Input,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
  OverlayDrawer,
  ProgressBar,
  Spinner,
  Switch,
  Text,
  DataGrid,
  DataGridBody,
  DataGridCell,
  DataGridHeader,
  DataGridHeaderCell,
  DataGridRow,
  createTableColumn,
  makeStyles,
  tokens,
  type TableColumnDefinition,
} from '@fluentui/react-components';
import {
  ArrowSyncRegular,
  DismissRegular,
  FolderRegular,
  LockClosedRegular,
  PlayRegular,
} from '@fluentui/react-icons';
import type { FileScanReport, ScanJobSummary } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBanner } from '../components/ErrorBanner';
import { KeyValue } from '../components/KeyValue';
import { Section } from '../components/Section';
import { StatusPill } from '../components/StatusPill';
import { useAsyncResource } from '../hooks/useAsyncResource';
import { describeError } from '../lib/errors';
import { formatBytes, formatDurationMs, formatNumber, formatScore, formatTimestamp } from '../lib/format';
import { resolveQuickScanTargets } from '../lib/quickTargets';
import { RISK_LEVEL_LABELS, SCAN_STATE_LABELS, riskTone, scanStateTone } from '../lib/severity';
import { useQuarantine } from '../state/QuarantineProvider';
import { isTerminalScanState, useScanJobs } from '../state/ScanJobsProvider';
import { useSharedStyles } from '../styles/shared';

const useStyles = makeStyles({
  quickGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '8px',
  },
  quickButton: {
    justifyContent: 'flex-start',
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  progressBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    paddingTop: '8px',
  },
  mono: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    overflowWrap: 'anywhere',
  },
  cellMono: {
    display: 'block',
    maxWidth: '260px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
  },
  resultsGrid: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  actionCell: {
    display: 'flex',
    gap: '4px',
  },
});

export function ScanCenterPage() {
  const styles = useStyles();
  const shared = useSharedStyles();
  const { jobs, progressByJob, loading, error, refresh, startScan, cancel, results, loadResults, clearResults } =
    useScanJobs();
  const { quarantine } = useQuarantine();

  const [pathInput, setPathInput] = useState('');
  const [recursive, setRecursive] = useState(true);
  const [starting, setStarting] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [openJobId, setOpenJobId] = useState<string | null>(null);
  const [quarantiningPath, setQuarantiningPath] = useState<string | null>(null);
  const [quarantineFeedback, setQuarantineFeedback] = useState<{
    intent: 'success' | 'error';
    title: string;
    message: string;
  } | null>(null);

  const quickTargets = useAsyncResource(resolveQuickScanTargets, []);

  const activeJobs = useMemo(() => jobs.filter((job) => !isTerminalScanState(job.state)), [jobs]);
  const primaryActive = activeJobs.length > 0 ? activeJobs[0] : null;
  const primaryProgress = primaryActive ? progressByJob[primaryActive.id] : undefined;
  const openJob = openJobId === null ? null : jobs.find((job) => job.id === openJobId) ?? null;

  const runScan = useCallback(
    async (path: string) => {
      const trimmed = path.trim();
      if (!trimmed) {
        setScanError('Enter a path to scan.');
        return;
      }
      setStarting(true);
      setScanError(null);
      try {
        await startScan(trimmed, recursive);
      } catch (startError) {
        setScanError(describeError(startError));
      } finally {
        setStarting(false);
      }
    },
    [recursive, startScan],
  );

  const onCancel = useCallback(
    async (jobId: string) => {
      setCancelError(null);
      try {
        await cancel(jobId);
      } catch (cancelScanError) {
        setCancelError(describeError(cancelScanError));
      }
    },
    [cancel],
  );

  const openResults = useCallback(
    (jobId: string) => {
      setOpenJobId(jobId);
      void loadResults(jobId);
    },
    [loadResults],
  );

  const closeResults = useCallback(() => {
    setOpenJobId(null);
    clearResults();
  }, [clearResults]);

  const onQuarantine = useCallback(
    async (path: string, reason: string) => {
      setQuarantiningPath(path);
      setQuarantineFeedback(null);
      try {
        const record = await quarantine(path, reason);
        setQuarantineFeedback({
          intent: 'success',
          title: 'Quarantined',
          message: `Stored a copy in the local vault as ${record.id}. The original file was left in place.`,
        });
      } catch (quarantineError) {
        setQuarantineFeedback({
          intent: 'error',
          title: 'Quarantine failed',
          message: describeError(quarantineError),
        });
      } finally {
        setQuarantiningPath(null);
      }
    },
    [quarantine],
  );

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            Scan center
          </Text>
          <Caption1 className={shared.muted}>
            On-demand file scanning. Results are stored locally in the security database.
          </Caption1>
        </div>
        <Button appearance="secondary" icon={<ArrowSyncRegular />} onClick={() => void refresh()} disabled={loading}>
          Refresh jobs
        </Button>
      </div>

      {error ? <ErrorBanner title="Could not load scan jobs" message={error} onRetry={() => void refresh()} /> : null}
      {scanError ? <ErrorBanner title="Scan could not start" message={scanError} /> : null}
      {cancelError ? <ErrorBanner title="Cancel failed" message={cancelError} /> : null}

      <Section title="Quick scans" subtitle="User profile locations resolved locally by the desktop app">
        {quickTargets.error ? (
          <MessageBar intent="warning">
            <MessageBarBody>{quickTargets.error} Use a custom path below instead.</MessageBarBody>
          </MessageBar>
        ) : null}
        {quickTargets.loading && quickTargets.data === null ? (
          <Spinner size="tiny" label="Resolving folders…" />
        ) : null}
        <div className={styles.quickGrid}>
          {(quickTargets.data?.targets ?? []).map((target) => (
            <Button
              key={target.id}
              appearance="secondary"
              icon={<FolderRegular />}
              className={styles.quickButton}
              onClick={() => void runScan(target.path)}
              disabled={starting}
              title={target.path}
            >
              {target.label}
            </Button>
          ))}
        </div>
      </Section>

      <Section title="Custom scan" subtitle="Scan any local path; symlinks are never followed by the scanner">
        <div className={styles.row}>
          <Input
            style={{ minWidth: '320px', flexGrow: 1 }}
            placeholder="C:\\Users\\you\\Downloads"
            value={pathInput}
            onChange={(_, data) => setPathInput(data.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                void runScan(pathInput);
              }
            }}
          />
          <Switch label="Recursive" checked={recursive} onChange={(_, data) => setRecursive(data.checked)} />
          <Button
            appearance="primary"
            icon={<PlayRegular />}
            onClick={() => void runScan(pathInput)}
            disabled={starting || pathInput.trim().length === 0}
          >
            Start scan
          </Button>
        </div>
      </Section>

      <Section
        title="Active scans"
        subtitle={activeJobs.length === 0 ? 'Nothing running' : `${activeJobs.length} scan(s) in progress`}
      >
        {primaryActive === null ? (
          <EmptyState title="No scan running" description="Start a quick or custom scan to see live progress here." />
        ) : (
          <div className={styles.progressBlock}>
            <div className={styles.row}>
              <Badge appearance="tint" color={scanStateTone(primaryProgress?.state ?? primaryActive.state)}>
                {SCAN_STATE_LABELS[primaryProgress?.state ?? primaryActive.state]}
              </Badge>
              <Text weight="semibold" className={styles.mono}>
                {primaryActive.path}
              </Text>
              <Caption1>
                {formatNumber(primaryProgress?.filesScanned ?? primaryActive.filesScanned)} files ·{' '}
                {formatNumber(primaryProgress?.detections ?? primaryActive.detections)} detections ·{' '}
                {formatNumber(primaryProgress?.errors ?? primaryActive.errors)} errors
              </Caption1>
            </div>
            <ProgressBar />
            <div className={styles.row}>
              <Caption1 className={styles.mono}>
                {primaryProgress?.currentPath ?? primaryActive.currentPath ?? 'Waiting for the scanner…'}
              </Caption1>
              <Button
                appearance="secondary"
                icon={<DismissRegular />}
                onClick={() => void onCancel(primaryActive.id)}
              >
                Cancel scan
              </Button>
            </div>
          </div>
        )}
      </Section>

      <Section title="Job history" subtitle="Most recent 50 scan jobs">
        {loading && jobs.length === 0 ? (
          <Spinner size="tiny" label="Loading jobs…" />
        ) : jobs.length === 0 ? (
          <EmptyState title="No scan jobs yet" description="Completed scans appear here with their counters." />
        ) : (
          <div className={shared.tableWrapper}>
            <DataGrid items={jobs} columns={jobColumns(onCancel, openResults)} getRowId={(job) => job.id} sortable>
              <DataGridHeader>
                <DataGridRow>
                  {({ renderHeaderCell }) => <DataGridHeaderCell>{renderHeaderCell()}</DataGridHeaderCell>}
                </DataGridRow>
              </DataGridHeader>
              <DataGridBody<ScanJobSummary>>
                {({ item, rowId }) => (
                  <DataGridRow<ScanJobSummary> key={rowId}>
                    {({ renderCell }) => <DataGridCell>{renderCell(item)}</DataGridCell>}
                  </DataGridRow>
                )}
              </DataGridBody>
            </DataGrid>
          </div>
        )}
      </Section>

      <OverlayDrawer
        open={openJobId !== null}
        onOpenChange={(_, data) => {
          if (!data.open) {
            closeResults();
          }
        }}
        position="end"
        size="large"
      >
        <DrawerHeader>
          <DrawerHeaderTitle>Scan results{openJob ? ` — ${openJob.path}` : ''}</DrawerHeaderTitle>
        </DrawerHeader>
        <DrawerBody>
          {quarantineFeedback ? (
            <MessageBar intent={quarantineFeedback.intent}>
              <MessageBarBody>
                <MessageBarTitle>{quarantineFeedback.title}</MessageBarTitle>
                {quarantineFeedback.message}
              </MessageBarBody>
            </MessageBar>
          ) : null}
          {results.loading ? (
            <Spinner label="Loading file reports…" />
          ) : results.error ? (
            <ErrorBanner title="Could not load results" message={results.error} />
          ) : results.items.length === 0 ? (
            <EmptyState
              title="No file reports stored"
              description="This job has no stored per-file reports yet (or the scan has not finished)."
            />
          ) : (
            <div className={styles.resultsGrid}>
              {openJob ? (
                <>
                  <KeyValue label="Job id" value={openJob.id} mono />
                  <KeyValue label="Started" value={formatTimestamp(openJob.startedAtMs)} />
                  <KeyValue label="Finished" value={formatTimestamp(openJob.finishedAtMs)} />
                </>
              ) : null}
              <div className={shared.tableWrapper}>
                <DataGrid
                  items={results.items}
                  columns={reportColumns(onQuarantine, quarantiningPath)}
                  getRowId={(report) => report.id}
                  sortable
                >
                  <DataGridHeader>
                    <DataGridRow>
                      {({ renderHeaderCell }) => <DataGridHeaderCell>{renderHeaderCell()}</DataGridHeaderCell>}
                    </DataGridRow>
                  </DataGridHeader>
                  <DataGridBody<FileScanReport>>
                    {({ item, rowId }) => (
                      <DataGridRow<FileScanReport> key={rowId}>
                        {({ renderCell }) => <DataGridCell>{renderCell(item)}</DataGridCell>}
                      </DataGridRow>
                    )}
                  </DataGridBody>
                </DataGrid>
              </div>
            </div>
          )}
        </DrawerBody>
      </OverlayDrawer>
    </div>
  );
}

function MonoCell({ text, title }: { text: string; title?: string }) {
  const styles = useStyles();
  return (
    <Caption1 className={styles.cellMono} title={title}>
      {text}
    </Caption1>
  );
}

function ActionsCell({ children }: { children: ReactNode }) {
  const styles = useStyles();
  return <div className={styles.actionCell}>{children}</div>;
}

function jobColumns(
  onCancel: (jobId: string) => Promise<void>,
  onOpenResults: (jobId: string) => void,
): TableColumnDefinition<ScanJobSummary>[] {
  return [
    createTableColumn<ScanJobSummary>({
      columnId: 'started',
      compare: (a, b) => a.startedAtMs - b.startedAtMs,
      renderHeaderCell: () => 'Started',
      renderCell: (job) => <Caption1>{formatTimestamp(job.startedAtMs)}</Caption1>,
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'path',
      compare: (a, b) => a.path.localeCompare(b.path),
      renderHeaderCell: () => 'Path',
      renderCell: (job) => <MonoCell text={job.path} title={job.path} />,
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'state',
      compare: (a, b) => a.state.localeCompare(b.state),
      renderHeaderCell: () => 'State',
      renderCell: (job) => (
        <Badge appearance="tint" color={scanStateTone(job.state)} size="small">
          {SCAN_STATE_LABELS[job.state] ?? job.state}
        </Badge>
      ),
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'files',
      compare: (a, b) => a.filesScanned - b.filesScanned,
      renderHeaderCell: () => 'Files',
      renderCell: (job) => <Caption1>{formatNumber(job.filesScanned)}</Caption1>,
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'detections',
      compare: (a, b) => a.detections - b.detections,
      renderHeaderCell: () => 'Detections',
      renderCell: (job) => (
        <Caption1>{job.detections > 0 ? formatNumber(job.detections) : '0'}</Caption1>
      ),
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'errors',
      renderHeaderCell: () => 'Errors',
      renderCell: (job) => <Caption1>{formatNumber(job.errors)}</Caption1>,
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'finished',
      compare: (a, b) => (a.finishedAtMs ?? 0) - (b.finishedAtMs ?? 0),
      renderHeaderCell: () => 'Finished',
      renderCell: (job) => <Caption1>{formatTimestamp(job.finishedAtMs)}</Caption1>,
    }),
    createTableColumn<ScanJobSummary>({
      columnId: 'actions',
      renderHeaderCell: () => 'Actions',
      renderCell: (job) => (
        <ActionsCell>
          <Button size="small" appearance="secondary" onClick={() => onOpenResults(job.id)} disabled={job.filesScanned === 0}>
            Results
          </Button>
          {!isTerminalScanState(job.state) ? (
            <Button size="small" appearance="subtle" onClick={() => void onCancel(job.id)}>
              Cancel
            </Button>
          ) : null}
        </ActionsCell>
      ),
    }),
  ];
}

/** Deterministic rule ids (or their source) that justify a manual quarantine. */
export function buildQuarantineReason(report: FileScanReport): string {
  const rules = report.detections.map((detection) => detection.ruleId || detection.source).join(', ');
  return `Manual quarantine from scan: ${rules}`;
}

function reportColumns(
  onQuarantine: (path: string, reason: string) => Promise<void>,
  busyPath: string | null,
): TableColumnDefinition<FileScanReport>[] {
  return [
    createTableColumn<FileScanReport>({
      columnId: 'file',
      compare: (a, b) => a.file.path.localeCompare(b.file.path),
      renderHeaderCell: () => 'File',
      renderCell: (report) => <MonoCell text={report.file.path} title={report.file.path} />,
    }),
    createTableColumn<FileScanReport>({
      columnId: 'risk',
      compare: (a, b) => a.assessment.score - b.assessment.score,
      renderHeaderCell: () => 'Risk',
      renderCell: (report) => (
        <Badge appearance="tint" color={riskTone(report.assessment.level)} size="small">
          {`${RISK_LEVEL_LABELS[report.assessment.level] ?? report.assessment.level} · ${formatScore(report.assessment.score)}`}
        </Badge>
      ),
    }),
    createTableColumn<FileScanReport>({
      columnId: 'detections',
      compare: (a, b) => a.detections.length - b.detections.length,
      renderHeaderCell: () => 'Detections',
      renderCell: (report) => <Caption1>{formatNumber(report.detections.length)}</Caption1>,
    }),
    createTableColumn<FileScanReport>({
      columnId: 'size',
      compare: (a, b) => a.file.size - b.file.size,
      renderHeaderCell: () => 'Size',
      renderCell: (report) => <Caption1>{formatBytes(report.file.size)}</Caption1>,
    }),
    createTableColumn<FileScanReport>({
      columnId: 'duration',
      compare: (a, b) => a.durationMs - b.durationMs,
      renderHeaderCell: () => 'Duration',
      renderCell: (report) => <Caption1>{formatDurationMs(report.durationMs)}</Caption1>,
    }),
    createTableColumn<FileScanReport>({
      columnId: 'cache',
      renderHeaderCell: () => 'Cached',
      renderCell: (report) =>
        report.cacheHit ? (
          <StatusPill label="Cache hit" tone="informative" size="small" />
        ) : (
          <Caption1>—</Caption1>
        ),
    }),
    createTableColumn<FileScanReport>({
      columnId: 'errors',
      renderHeaderCell: () => 'Errors',
      renderCell: (report) =>
        report.errors.length > 0 ? (
          <Caption1 title={report.errors.join('\n')}>{formatNumber(report.errors.length)}</Caption1>
        ) : (
          <Caption1>0</Caption1>
        ),
    }),
    createTableColumn<FileScanReport>({
      columnId: 'actions',
      renderHeaderCell: () => 'Actions',
      renderCell: (report) =>
        report.detections.length > 0 ? (
          <ActionsCell>
            <Button
              size="small"
              appearance="secondary"
              icon={<LockClosedRegular />}
              disabled={busyPath === report.file.path}
              onClick={() => void onQuarantine(report.file.path, buildQuarantineReason(report))}
            >
              Quarantine
            </Button>
          </ActionsCell>
        ) : (
          <Caption1>—</Caption1>
        ),
    }),
  ];
}
