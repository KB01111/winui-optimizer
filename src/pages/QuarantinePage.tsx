import { useCallback, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Caption1,
  DataGrid,
  DataGridBody,
  DataGridCell,
  DataGridHeader,
  DataGridHeaderCell,
  DataGridRow,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  DialogTrigger,
  Input,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
  Spinner,
  Text,
  createTableColumn,
  makeStyles,
  tokens,
  type TableColumnDefinition,
} from '@fluentui/react-components';
import { ArrowSyncRegular, DeleteRegular } from '@fluentui/react-icons';
import type { QuarantineRecord } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBanner } from '../components/ErrorBanner';
import { KeyValue } from '../components/KeyValue';
import { Section } from '../components/Section';
import { describeError } from '../lib/errors';
import { formatBytes, formatTimestamp } from '../lib/format';
import { QUARANTINE_STATUS_LABELS, quarantineStatusTone } from '../lib/severity';
import { useQuarantine } from '../state/QuarantineProvider';
import { useSharedStyles } from '../styles/shared';

const useStyles = makeStyles({
  formRow: {
    display: 'flex',
    alignItems: 'flex-end',
    gap: '8px',
    flexWrap: 'wrap',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    minWidth: '260px',
    flexGrow: 1,
  },
  actionCell: {
    display: 'flex',
    gap: '4px',
    alignItems: 'center',
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
  cellName: {
    display: 'block',
    maxWidth: '260px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  cellReason: {
    display: 'block',
    maxWidth: '280px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  centered: {
    display: 'flex',
    justifyContent: 'center',
    padding: '24px',
  },
  detailScroll: {
    maxHeight: 'calc(100vh - 220px)',
    overflowY: 'auto',
    paddingRight: '4px',
  },
});

const HASH_PREVIEW_LENGTH = 16;

type Feedback = {
  intent: 'success' | 'error';
  title: string;
  message: string;
};

interface RecordActionHandlers {
  onRestore: (record: QuarantineRecord) => void;
  onConfirmDelete: (record: QuarantineRecord) => void;
  onDeleteOpenChange: (recordId: string, open: boolean) => void;
  busyId: string | null;
  deleteTargetId: string | null;
}

function NameCell({ record }: { record: QuarantineRecord }) {
  const styles = useStyles();
  return (
    <Text className={styles.cellName} title={record.originalPath}>
      {record.originalName}
    </Text>
  );
}

function HashCell({ record }: { record: QuarantineRecord }) {
  const styles = useStyles();
  const preview =
    record.sha256.length > HASH_PREVIEW_LENGTH
      ? `${record.sha256.slice(0, HASH_PREVIEW_LENGTH)}…`
      : record.sha256;
  return (
    <Caption1 className={styles.cellMono} title={record.sha256}>
      {preview}
    </Caption1>
  );
}

function ReasonCell({ record }: { record: QuarantineRecord }) {
  const styles = useStyles();
  return (
    <Caption1 className={styles.cellReason} title={record.reason}>
      {record.reason}
    </Caption1>
  );
}

function RecordActionsCell({
  record,
  onRestore,
  onConfirmDelete,
  onDeleteOpenChange,
  busy,
  deleteOpen,
}: {
  record: QuarantineRecord;
  onRestore: (record: QuarantineRecord) => void;
  onConfirmDelete: (record: QuarantineRecord) => void;
  onDeleteOpenChange: (recordId: string, open: boolean) => void;
  busy: boolean;
  deleteOpen: boolean;
}) {
  const styles = useStyles();
  const restorable = record.status === 'quarantined';
  return (
    <div className={styles.actionCell}>
      <Button
        size="small"
        appearance="secondary"
        disabled={!restorable || busy}
        onClick={() => onRestore(record)}
      >
        Restore
      </Button>
      <Dialog open={deleteOpen} onOpenChange={(_, data) => onDeleteOpenChange(record.id, data.open)}>
        <DialogTrigger action="open">
          <Button size="small" appearance="secondary" icon={<DeleteRegular />} disabled={!restorable || busy}>
            Delete
          </Button>
        </DialogTrigger>
        <DialogSurface>
          <DialogBody>
            <DialogTitle>Delete this quarantined copy?</DialogTitle>
            <DialogContent>
              This permanently removes the vault copy of {record.originalName} ({record.sha256}). The
              original file location is not touched by this action — only the stored copy in the
              quarantine vault is removed, and it cannot be undone.
            </DialogContent>
            <DialogActions>
              <DialogTrigger action="close">
                <Button appearance="secondary">Cancel</Button>
              </DialogTrigger>
              <Button appearance="primary" onClick={() => onConfirmDelete(record)}>
                Delete copy permanently
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </div>
  );
}

function recordColumns(handlers: RecordActionHandlers): TableColumnDefinition<QuarantineRecord>[] {
  const { onRestore, onConfirmDelete, onDeleteOpenChange, busyId, deleteTargetId } = handlers;
  return [
    createTableColumn<QuarantineRecord>({
      columnId: 'quarantinedAt',
      compare: (a, b) => a.quarantinedAtMs - b.quarantinedAtMs,
      renderHeaderCell: () => 'Quarantined',
      renderCell: (record) => <Caption1>{formatTimestamp(record.quarantinedAtMs)}</Caption1>,
    }),
    createTableColumn<QuarantineRecord>({
      columnId: 'name',
      compare: (a, b) => a.originalName.localeCompare(b.originalName),
      renderHeaderCell: () => 'File',
      renderCell: (record) => <NameCell record={record} />,
    }),
    createTableColumn<QuarantineRecord>({
      columnId: 'size',
      compare: (a, b) => a.size - b.size,
      renderHeaderCell: () => 'Size',
      renderCell: (record) => <Caption1>{formatBytes(record.size)}</Caption1>,
    }),
    createTableColumn<QuarantineRecord>({
      columnId: 'sha256',
      compare: (a, b) => a.sha256.localeCompare(b.sha256),
      renderHeaderCell: () => 'SHA-256',
      renderCell: (record) => <HashCell record={record} />,
    }),
    createTableColumn<QuarantineRecord>({
      columnId: 'status',
      compare: (a, b) => a.status.localeCompare(b.status),
      renderHeaderCell: () => 'Status',
      renderCell: (record) => (
        <Badge appearance="tint" color={quarantineStatusTone(record.status)} size="small">
          {QUARANTINE_STATUS_LABELS[record.status] ?? record.status}
        </Badge>
      ),
    }),
    createTableColumn<QuarantineRecord>({
      columnId: 'reason',
      compare: (a, b) => a.reason.localeCompare(b.reason),
      renderHeaderCell: () => 'Reason',
      renderCell: (record) => <ReasonCell record={record} />,
    }),
    createTableColumn<QuarantineRecord>({
      columnId: 'actions',
      renderHeaderCell: () => 'Actions',
      renderCell: (record) => (
        <RecordActionsCell
          record={record}
          onRestore={onRestore}
          onConfirmDelete={onConfirmDelete}
          onDeleteOpenChange={onDeleteOpenChange}
          busy={busyId === record.id}
          deleteOpen={deleteTargetId === record.id}
        />
      ),
    }),
  ];
}

export function QuarantinePage() {
  const styles = useStyles();
  const shared = useSharedStyles();
  const { records, loading, error, refresh, quarantine, restore, remove } = useQuarantine();

  const [pathInput, setPathInput] = useState('');
  const [reasonInput, setReasonInput] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [manualFeedback, setManualFeedback] = useState<Feedback | null>(null);
  const [actionFeedback, setActionFeedback] = useState<Feedback | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedRecord = useMemo(
    () => records.find((record) => record.id === selectedId) ?? null,
    [records, selectedId],
  );

  const onManualQuarantine = useCallback(async () => {
    const path = pathInput.trim();
    const reason = reasonInput.trim();
    if (path.length === 0 || reason.length === 0) {
      setManualFeedback({
        intent: 'error',
        title: 'Path and reason are required',
        message:
          path.length === 0
            ? 'Enter the absolute path of the file to quarantine.'
            : 'Enter a reason so the quarantine action is auditable.',
      });
      return;
    }
    setSubmitting(true);
    setManualFeedback(null);
    try {
      const record = await quarantine(path, reason);
      setManualFeedback({
        intent: 'success',
        title: 'Quarantined',
        message: `Stored a copy in the local vault as ${record.id}. The original file was left in place.`,
      });
      setPathInput('');
      setReasonInput('');
    } catch (quarantineError) {
      setManualFeedback({
        intent: 'error',
        title: 'Quarantine failed',
        message: describeError(quarantineError),
      });
    } finally {
      setSubmitting(false);
    }
  }, [pathInput, reasonInput, quarantine]);

  const onRestore = useCallback(
    async (record: QuarantineRecord) => {
      setBusyId(record.id);
      setActionFeedback(null);
      try {
        const result = await restore(record.id);
        if (result.success) {
          setActionFeedback({
            intent: 'success',
            title: 'Restore requested',
            message: result.restoredPath
              ? `${result.message} — restored to ${result.restoredPath}`
              : result.message,
          });
        } else {
          setActionFeedback({
            intent: 'error',
            title: 'Restore failed',
            message: result.message,
          });
        }
      } catch (restoreError) {
        setActionFeedback({
          intent: 'error',
          title: 'Restore failed',
          message: describeError(restoreError),
        });
      } finally {
        setBusyId(null);
      }
    },
    [restore],
  );

  const onConfirmDelete = useCallback(
    async (record: QuarantineRecord) => {
      setDeleteTargetId(null);
      setBusyId(record.id);
      setActionFeedback(null);
      try {
        const deleted = await remove(record.id);
        setActionFeedback(
          deleted
            ? {
                intent: 'success',
                title: 'Quarantined copy deleted',
                message: 'The vault copy was permanently removed. The original file location was not touched.',
              }
            : {
                intent: 'error',
                title: 'Delete failed',
                message: 'The backend did not confirm that the quarantined copy was deleted.',
              },
        );
      } catch (deleteError) {
        setActionFeedback({
          intent: 'error',
          title: 'Delete failed',
          message: describeError(deleteError),
        });
      } finally {
        setBusyId(null);
      }
    },
    [remove],
  );

  const onDeleteOpenChange = useCallback((recordId: string, open: boolean) => {
    setDeleteTargetId(open ? recordId : null);
  }, []);

  const columns = useMemo(
    () =>
      recordColumns({
        onRestore: (record) => void onRestore(record),
        onConfirmDelete: (record) => void onConfirmDelete(record),
        onDeleteOpenChange,
        busyId,
        deleteTargetId,
      }),
    [onRestore, onConfirmDelete, onDeleteOpenChange, busyId, deleteTargetId],
  );

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            Quarantine
          </Text>
          <Caption1 className={shared.muted}>
            Quarantined copies are stored in the local vault. The original file is never deleted.
          </Caption1>
        </div>
        <Button
          appearance="secondary"
          icon={<ArrowSyncRegular />}
          onClick={() => void refresh()}
          disabled={loading}
        >
          Refresh
        </Button>
      </div>

      {error ? (
        <ErrorBanner
          title="Could not load quarantined files"
          message={error}
          onRetry={() => void refresh()}
        />
      ) : null}

      <Section
        title="Manual quarantine"
        subtitle="Copies the file into the local vault; the original file stays where it is"
      >
        <div className={styles.formRow}>
          <div className={styles.field}>
            <Caption1>Absolute file path</Caption1>
            <Input
              placeholder={'C:\\Users\\you\\Downloads\\suspicious.exe'}
              value={pathInput}
              onChange={(_, data) => setPathInput(data.value)}
              disabled={submitting}
            />
          </div>
          <div className={styles.field}>
            <Caption1>Reason</Caption1>
            <Input
              placeholder="Manual quarantine from the dashboard"
              value={reasonInput}
              onChange={(_, data) => setReasonInput(data.value)}
              disabled={submitting}
            />
          </div>
          <Button
            appearance="primary"
            onClick={() => void onManualQuarantine()}
            disabled={submitting}
          >
            {submitting ? 'Quarantining…' : 'Quarantine file'}
          </Button>
        </div>
        {manualFeedback ? (
          <MessageBar intent={manualFeedback.intent}>
            <MessageBarBody>
              <MessageBarTitle>{manualFeedback.title}</MessageBarTitle>
              {manualFeedback.message}
            </MessageBarBody>
          </MessageBar>
        ) : null}
      </Section>

      <div className={shared.split}>
        <Section
          title="Quarantined files"
          subtitle={
            records.length === 0
              ? 'No vault entries'
              : `${records.length} vault entr${records.length === 1 ? 'y' : 'ies'}`
          }
        >
          {actionFeedback ? (
            <MessageBar intent={actionFeedback.intent}>
              <MessageBarBody>
                <MessageBarTitle>{actionFeedback.title}</MessageBarTitle>
                {actionFeedback.message}
              </MessageBarBody>
            </MessageBar>
          ) : null}

          {loading && records.length === 0 ? (
            <div className={styles.centered}>
              <Spinner label="Loading quarantined files…" />
            </div>
          ) : null}

          {!loading && error === null && records.length === 0 ? (
            <EmptyState
              title="No files are quarantined"
              description="Nothing has been copied into the quarantine vault yet. Files you quarantine from the scan center or with the manual action above appear here."
            />
          ) : null}

          {records.length > 0 ? (
            <div className={shared.tableWrapper}>
              <DataGrid
                items={records}
                columns={columns}
                getRowId={(record) => record.id}
                selectionMode="single"
                selectedItems={selectedId === null ? [] : [selectedId]}
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
                <DataGridBody<QuarantineRecord>>
                  {({ item, rowId }) => (
                    <DataGridRow<QuarantineRecord> key={rowId}>
                      {({ renderCell }) => <DataGridCell>{renderCell(item)}</DataGridCell>}
                    </DataGridRow>
                  )}
                </DataGridBody>
              </DataGrid>
            </div>
          ) : null}
        </Section>

        <Section title="Record detail" subtitle="Selection from the table">
          <div className={styles.detailScroll}>
            {selectedRecord === null ? (
              <EmptyState
                title="No record selected"
                description="Select a row to inspect the stored copy, its hashes and the reason it was quarantined."
              />
            ) : (
              <>
                <KeyValue label="Record id" value={selectedRecord.id} mono />
                <KeyValue label="Original path" value={selectedRecord.originalPath} mono />
                <KeyValue label="Original name" value={selectedRecord.originalName} />
                <KeyValue label="Stored vault path" value={selectedRecord.storedPath} mono />
                <KeyValue label="SHA-256" value={selectedRecord.sha256} mono />
                <KeyValue label="Size" value={formatBytes(selectedRecord.size)} />
                <KeyValue label="Quarantined at" value={formatTimestamp(selectedRecord.quarantinedAtMs)} />
                <KeyValue label="Restored at" value={formatTimestamp(selectedRecord.restoredAtMs)} />
                <KeyValue label="Detection id" value={selectedRecord.detectionId} mono />
                <KeyValue label="Reason" value={selectedRecord.reason} />
                <KeyValue
                  label="Identity verified"
                  value={selectedRecord.identityVerified ? 'Verified' : 'Not verified'}
                />
                <KeyValue label="Status" value={QUARANTINE_STATUS_LABELS[selectedRecord.status] ?? selectedRecord.status} />
              </>
            )}
          </div>
        </Section>
      </div>
    </div>
  );
}
