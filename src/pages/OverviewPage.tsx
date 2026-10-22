import { useCallback, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Caption1,
  Divider,
  Spinner,
  Text,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import {
  ArrowSyncRegular,
  CheckmarkCircleRegular,
  ErrorCircleRegular,
  InfoRegular,
  ShieldCheckmarkRegular,
  WarningRegular,
} from '@fluentui/react-icons';
import { listEvents, startMonitoring, stopMonitoring } from '../api/commands';
import type { SecurityEvent } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBanner } from '../components/ErrorBanner';
import { KeyValue } from '../components/KeyValue';
import { Metric } from '../components/Metric';
import { Section } from '../components/Section';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusPill } from '../components/StatusPill';
import { useAsyncResource } from '../hooks/useAsyncResource';
import { useNow } from '../hooks/useNow';
import { summarizeProtection } from '../lib/protection';
import {
  PROVIDER_STATUS_LABELS,
  kindLabel,
  providerStatusTone,
  scanStateTone,
} from '../lib/severity';
import { describeError } from '../lib/errors';
import {
  formatBytes,
  formatDateOnly,
  formatNumber,
  formatRelative,
  formatTimestamp,
  formatUptime,
  formatUsd,
} from '../lib/format';
import { isTerminalScanState, useScanJobs } from '../state/ScanJobsProvider';
import { useSystemStatus } from '../state/SystemStatusProvider';
import { useSharedStyles } from '../styles/shared';

const useStyles = makeStyles({
  detectionRow: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    padding: '8px 0',
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
    ':last-child': { borderBottom: 'none' },
  },
  detectionHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  detectionMeta: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    color: tokens.colorNeutralForeground3,
  },
  metricRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
    gap: '16px',
  },
  reasonList: {
    margin: 0,
    paddingLeft: '18px',
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    color: tokens.colorNeutralForeground2,
  },
  spinWrap: {
    display: 'flex',
    justifyContent: 'center',
    padding: '24px',
  },
});

export function OverviewPage() {
  const styles = useStyles();
  const shared = useSharedStyles();
  const { status, error, loading, lastUpdatedMs, refresh } = useSystemStatus();
  const { jobs, progressByJob, activeJobIds } = useScanJobs();
  const now = useNow(10_000);
  const [monitoringBusy, setMonitoringBusy] = useState(false);
  const [monitoringError, setMonitoringError] = useState<string | null>(null);

  const detectionsResource = useAsyncResource<SecurityEvent[]>(
    async () => {
      const page = await listEvents({ limit: 10, offset: 0, kind: 'detection' });
      return page.items ?? [];
    },
    [],
    30_000,
  );

  const protection = useMemo(() => summarizeProtection(status), [status]);
  const activeJobs = useMemo(
    () => jobs.filter((job) => !isTerminalScanState(job.state)),
    [jobs],
  );

  const toggleMonitoring = useCallback(
    async (action: 'start' | 'stop') => {
      setMonitoringBusy(true);
      setMonitoringError(null);
      try {
        if (action === 'start') {
          await startMonitoring();
        } else {
          await stopMonitoring();
        }
        await refresh();
      } catch (actionError) {
        setMonitoringError(describeError(actionError));
      } finally {
        setMonitoringBusy(false);
      }
    },
    [refresh],
  );

  const engine = status?.engine;
  const defender = status?.defender;
  const ai = status?.ai;
  const hardware = status?.hardware;
  const identity = status?.packageIdentity;
  const service = status?.service;

  const engineRunning =
    typeof engine?.running === 'boolean' ? engine.running : null;
  // The desktop engine has no separate monitoring flag: a running engine is
  // the process actively monitoring telemetry.
  const monitoring = engineRunning;

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            Overview
          </Text>
          <Caption1 className={shared.muted}>
            {status ? `${status.productName} · version ${status.version}` : 'Waiting for the security service…'}
          </Caption1>
        </div>
        <div className={shared.toolbar}>
          {lastUpdatedMs !== null ? (
            <Caption1 className={shared.muted}>Updated {formatRelative(lastUpdatedMs, now)}</Caption1>
          ) : null}
          <Button
            appearance="secondary"
            icon={<ArrowSyncRegular />}
            onClick={() => {
              void refresh();
              detectionsResource.reload();
            }}
            disabled={loading}
          >
            Refresh
          </Button>
        </div>
      </div>

      {error ? <ErrorBanner title="Engine status unavailable" message={error} onRetry={() => void refresh()} /> : null}

      {loading && !status ? (
        <div className={styles.spinWrap}>
          <Spinner label="Loading system status…" />
        </div>
      ) : null}

      {!loading && !status && !error ? (
        <EmptyState
          title="No system status yet"
          description="The dashboard has not received a status payload from the security engine."
        />
      ) : null}

      {status ? (
        <>
          <Section
            title="Protection status"
            subtitle="Derived from the engine and Microsoft Defender read-only status"
            action={
              <StatusPill
                label={protection.label}
                tone={
                  protection.tone === 'good'
                    ? 'success'
                    : protection.tone === 'warn'
                      ? 'warning'
                      : protection.tone === 'bad'
                        ? 'danger'
                        : 'subtle'
                }
                icon={
                  protection.tone === 'good' ? (
                    <CheckmarkCircleRegular />
                  ) : protection.tone === 'bad' ? (
                    <ErrorCircleRegular />
                  ) : protection.tone === 'warn' ? (
                    <WarningRegular />
                  ) : (
                    <InfoRegular />
                  )
                }
              />
            }
          >
            <ul className={styles.reasonList}>
              {protection.reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </Section>

          <div className={shared.grid}>
            <Section
              title="Microsoft Defender"
              subtitle="Read-only status query; the dashboard never changes Defender settings"
              action={
                <StatusPill
                  label={defender?.available ? 'Available' : 'Unavailable'}
                  tone={defender?.available ? 'success' : 'danger'}
                />
              }
            >
              {defender ? (
                <>
                  {defender.queryError ? (
                    <ErrorBanner title="Defender query failed" message={defender.queryError} />
                  ) : null}
                  <KeyValue
                    label="Real-time protection"
                    value={defender.realtimeEnabled ? 'Enabled' : 'Disabled'}
                  />
                  <KeyValue label="Antivirus" value={defender.antivirusEnabled ? 'Enabled' : 'Disabled'} />
                  <KeyValue label="Antispyware" value={defender.antispywareEnabled ? 'Enabled' : 'Disabled'} />
                  <KeyValue label="Tamper protection" value={defender.tamperProtected ? 'Enabled' : 'Disabled'} />
                  <KeyValue label="Engine version" value={defender.engineVersion} mono />
                  <KeyValue label="Signatures" value={defender.signatureVersion} mono />
                  <KeyValue
                    label="Signature age"
                    value={
                      typeof defender.signatureAgeDays === 'number'
                        ? `${formatNumber(defender.signatureAgeDays)} day(s)`
                        : undefined
                    }
                  />
                  <KeyValue label="Definition status" value={defender.definitionStatus} />
                  <KeyValue label="Last quick scan" value={formatDateOnly(defender.lastQuickScanMs)} />
                  <KeyValue label="Last full scan" value={formatDateOnly(defender.lastFullScanMs)} />
                  <KeyValue label="Threats detected" value={formatNumber(defender.threatsDetected)} />
                  <KeyValue label="Checked at" value={formatTimestamp(defender.checkedAtMs)} />
                </>
              ) : (
                <EmptyState title="Defender status missing" description="The status payload did not include Defender data." />
              )}
            </Section>

            <Section
              title="Monitoring"
              subtitle="Security engine process and service link"
              action={
                <div className={shared.toolbar}>
                  <StatusPill
                    label={
                      engineRunning === null ? 'Engine state unknown' : engineRunning ? 'Engine running' : 'Engine stopped'
                    }
                    tone={engineRunning === null ? 'subtle' : engineRunning ? 'success' : 'danger'}
                    icon={<ShieldCheckmarkRegular />}
                  />
                  <StatusPill
                    label={
                      monitoring === null
                        ? 'Monitoring unknown'
                        : !monitoring
                          ? 'Not monitoring'
                          : engine?.monitoringIsPreventive
                            ? 'Preventive monitoring'
                            : 'Observe-only monitoring'
                    }
                    tone={monitoring === null ? 'subtle' : monitoring ? 'brand' : 'warning'}
                  />
                </div>
              }
            >
              {monitoringError ? <ErrorBanner title="Monitoring command failed" message={monitoringError} /> : null}
              <div className={shared.toolbar}>
                <Button
                  appearance="primary"
                  disabled={monitoringBusy || engineRunning === true}
                  onClick={() => void toggleMonitoring('start')}
                >
                  Start monitoring
                </Button>
                <Button
                  appearance="secondary"
                  disabled={monitoringBusy || engineRunning === false}
                  onClick={() => void toggleMonitoring('stop')}
                >
                  Stop monitoring
                </Button>
              </div>
              <Divider />
              <KeyValue label="Mode" value={engine?.mode} />
              <KeyValue label="Uptime" value={engine ? formatUptime(engine.uptimeSecs) : undefined} />
              <KeyValue label="Started at" value={formatTimestamp(engine?.startedAtMs)} />
              <KeyValue label="Telemetry source" value={engine?.telemetrySource} mono />
              <KeyValue
                label="Telemetry available"
                value={engine ? (engine.telemetryAvailable ? 'Yes' : 'No') : undefined}
              />
              <KeyValue
                label="Preventive monitoring"
                value={engine ? (engine.monitoringIsPreventive ? 'Yes' : 'No (observe only)') : undefined}
              />
              <KeyValue label="Events processed" value={formatNumber(engine?.eventsProcessed)} />
              <KeyValue label="Correlated chains" value={formatNumber(engine?.correlatedChains)} />
              <KeyValue label="Detections" value={formatNumber(engine?.detections)} />
              <KeyValue label="Scans completed" value={formatNumber(engine?.scansCompleted)} />
              <KeyValue label="Dropped events" value={formatNumber(engine?.droppedEvents)} />
              <Divider />
              <KeyValue
                label="Privileged service"
                value={
                  service
                    ? service.available
                      ? service.connected
                        ? 'Available · connected'
                        : 'Available · disconnected'
                      : 'Not available'
                    : undefined
                }
              />
              <KeyValue label="Pipe" value={service?.pipeName} mono />
              <KeyValue label="Service version" value={service?.version} mono />
              {service?.lastError ? <ErrorBanner title="Service error" message={service.lastError} /> : null}
            </Section>

            <Section
              title="Active scans"
              subtitle={activeJobIds.length > 0 ? `${activeJobIds.length} job(s) in progress` : 'No scan running'}
            >
              {activeJobs.length === 0 ? (
                <EmptyState
                  title="No scan is running"
                  description="Start a quick scan from Scan Center to see live progress here."
                />
              ) : (
                activeJobs.map((job) => {
                  const progress = progressByJob[job.id];
                  const filesScanned = progress?.filesScanned ?? job.filesScanned;
                  const detections = progress?.detections ?? job.detections;
                  const errors = progress?.errors ?? job.errors;
                  return (
                    <div key={job.id} className={styles.detectionRow}>
                      <div className={styles.detectionHeader}>
                        <Badge appearance="tint" color={scanStateTone(progress?.state ?? job.state)} size="small">
                          {progress?.state ?? job.state}
                        </Badge>
                        <Text weight="semibold">{job.path}</Text>
                        {job.recursive ? (
                          <Badge appearance="tint" color="subtle" size="small">
                            Recursive
                          </Badge>
                        ) : null}
                      </div>
                      <div className={styles.detectionMeta}>
                        <Caption1>{`${formatNumber(filesScanned)} files`}</Caption1>
                        <Caption1>{`${formatNumber(detections)} detections`}</Caption1>
                        <Caption1>{`${formatNumber(errors)} errors`}</Caption1>
                        <Caption1>{progress?.currentPath ?? job.currentPath ?? '—'}</Caption1>
                      </div>
                    </div>
                  );
                })
              )}
            </Section>

            <Section
              title="Recent detections"
              subtitle="Latest events with deterministic detections"
              action={
                <Button appearance="subtle" icon={<ArrowSyncRegular />} onClick={detectionsResource.reload}>
                  Refresh
                </Button>
              }
            >
              {detectionsResource.error ? (
                <ErrorBanner
                  title="Could not load recent detections"
                  message={detectionsResource.error}
                  onRetry={detectionsResource.reload}
                />
              ) : null}
              {detectionsResource.loading && detectionsResource.data === null ? (
                <div className={styles.spinWrap}>
                  <Spinner size="tiny" label="Loading detections…" />
                </div>
              ) : null}
              {!detectionsResource.loading && !detectionsResource.error && (detectionsResource.data?.length ?? 0) === 0 ? (
                <EmptyState
                  title="No detections recorded"
                  description="Nothing malicious has been detected yet. Events will appear here as soon as the engine flags one."
                />
              ) : null}
              {(detectionsResource.data ?? []).map((event) => (
                <div key={event.id} className={styles.detectionRow}>
                  <div className={styles.detectionHeader}>
                    <SeverityBadge severity={event.severity} />
                    <Text weight="semibold">{event.title || kindLabel(event.kind)}</Text>
                  </div>
                  <div className={styles.detectionMeta}>
                    <Caption1>{formatTimestamp(event.timestampMs)}</Caption1>
                    {event.assessment ? (
                      <Caption1>{`Risk score ${event.assessment.score.toFixed(1)} (${event.assessment.level})`}</Caption1>
                    ) : null}
                    {event.file?.sha256 ? <Caption1 className={shared.mono}>{`${event.file.sha256.slice(0, 16)}…`}</Caption1> : null}
                    {event.process?.name ? <Caption1>{event.process.name}</Caption1> : null}
                  </div>
                </div>
              ))}
            </Section>

            <Section
              title="AI providers"
              subtitle="Advisory classification only; quarantine is decided by deterministic policy"
              action={
                ai ? (
                  <StatusPill
                    label={ai.mode === 'offline' ? 'Offline mode' : `${ai.mode} mode`}
                    tone={ai.mode === 'offline' ? 'subtle' : ai.configured ? 'brand' : 'warning'}
                  />
                ) : null
              }
            >
              {ai ? (
                <>
                  <KeyValue label="Configured" value={ai.configured ? 'Yes' : 'No'} />
                  <KeyValue label="Offline capable" value={ai.offlineCapable ? 'Yes' : 'No'} />
                  <KeyValue label="Primary model" value={ai.primaryModel} mono />
                  <KeyValue label="Escalation model" value={ai.escalationModel} mono />
                  <KeyValue label="Cloud state sharing" value={ai.allowCloudState ? 'Allowed' : 'Disabled'} />
                  <KeyValue
                    label="Local route"
                    value={`${ai.local.route.primary} (fallback ${ai.local.route.fallback})`}
                  />
                  <KeyValue label="Local model" value={ai.local.model.name} mono />
                  <KeyValue label="Total cost" value={formatUsd(ai.totalCostUsd)} />
                  <KeyValue label="Requests" value={formatNumber(ai.requests)} />
                  <KeyValue label="Failures" value={formatNumber(ai.failures)} />
                  <Divider />
                  {ai.providers.length === 0 ? (
                    <Caption1 className={shared.muted}>
                      No provider health has been reported. The engine runs fully without AI providers.
                    </Caption1>
                  ) : (
                    ai.providers.map((provider) => (
                      <div key={`${provider.provider}-${provider.model}`} className={styles.detectionRow}>
                        <div className={styles.detectionHeader}>
                          <Badge
                            appearance="tint"
                            color={providerStatusTone(provider.status)}
                            size="small"
                          >
                            {PROVIDER_STATUS_LABELS[provider.status] ?? provider.status}
                          </Badge>
                          <Text weight="semibold">{provider.provider}</Text>
                          <Caption1 className={shared.muted}>{provider.model}</Caption1>
                        </div>
                        <div className={styles.detectionMeta}>
                          <Caption1>{`${formatNumber(provider.requests)} requests`}</Caption1>
                          <Caption1>{`${formatNumber(provider.failures)} failures`}</Caption1>
                          <Caption1>
                            {provider.lastLatencyMs !== null && provider.lastLatencyMs !== undefined
                              ? `${formatNumber(provider.lastLatencyMs)} ms`
                              : 'no latency'}
                          </Caption1>
                          <Caption1>{formatUsd(provider.totalCostUsd)}</Caption1>
                        </div>
                        {provider.lastError ? <Caption1>{provider.lastError}</Caption1> : null}
                      </div>
                    ))
                  )}
                </>
              ) : (
                <EmptyState title="AI status missing" description="The status payload did not include AI provider data." />
              )}
            </Section>

            <Section title="Hardware and resources" subtitle="Detected locally; used to route on-device inference">
              {hardware ? (
                <>
                  <div className={styles.metricRow}>
                    <Metric
                      label="Memory in use"
                      value={formatBytes((hardware.totalRamMb - hardware.availableRamMb) * 1024 * 1024, 0)}
                      hint={`${formatBytes(hardware.availableRamMb * 1024 * 1024, 0)} free of ${formatBytes(hardware.totalRamMb * 1024 * 1024, 0)}`}
                      tone={
                        hardware.totalRamMb > 0 && hardware.availableRamMb / hardware.totalRamMb < 0.1
                          ? 'warn'
                          : 'neutral'
                      }
                    />
                    <Metric
                      label="Logical cores"
                      value={formatNumber(hardware.logicalCores)}
                      hint={hardware.physicalCores ? `${formatNumber(hardware.physicalCores)} physical` : undefined}
                    />
                    <Metric
                      label="Battery"
                      value={hardware.battery.present ? `${hardware.battery.percent ?? '—'}%` : 'No battery'}
                      hint={
                        hardware.battery.present
                          ? hardware.battery.acOnline
                            ? 'AC power'
                            : 'On battery'
                          : 'Desktop or unknown'
                      }
                      tone={hardware.battery.present && !hardware.battery.acOnline ? 'warn' : 'neutral'}
                    />
                  </div>
                  <Divider />
                  <KeyValue label="CPU" value={hardware.cpuName} />
                  <KeyValue label="Architecture" value={hardware.cpuArch} mono />
                  <KeyValue
                    label="GPUs"
                    value={
                      hardware.gpus.length === 0
                        ? 'None reported'
                        : hardware.gpus.map((gpu) => `${gpu.name}${gpu.isDiscrete ? ' (discrete)' : ''}`).join(', ')
                    }
                  />
                  <KeyValue
                    label="NPU"
                    value={
                      hardware.npu
                        ? `${hardware.npu.name}${hardware.npu.available ? '' : ' (not available)'}`
                        : 'Not reported'
                    }
                  />
                </>
              ) : (
                <EmptyState title="Hardware profile missing" description="The status payload did not include hardware data." />
              )}
            </Section>

            <Section title="Local database" subtitle="Stored security records reported by the storage layer">
              <div className={styles.metricRow}>
                <Metric label="Events" value={formatNumber(status.storage.events)} />
                <Metric label="Detections" value={formatNumber(status.storage.detections)} />
                <Metric label="Quarantined" value={formatNumber(status.storage.quarantined)} />
                <Metric label="Scans" value={formatNumber(status.storage.scans)} />
              </div>
            </Section>

            <Section title="Package identity" subtitle="MSIX identity and execution context">
              <KeyValue label="Packaged" value={identity?.available ? 'Yes' : 'No'} />
              <KeyValue label="Family name" value={identity?.familyName} mono />
              <KeyValue label="Full name" value={identity?.fullName} mono />
              <KeyValue label="Publisher" value={identity?.publisher} />
              <KeyValue label="Version" value={identity?.version} />
              <KeyValue label="Install location" value={identity?.installLocation} mono />
              <KeyValue label="App user model id" value={identity?.appUserModelId} mono />
              <Divider />
              <KeyValue label="Elevated" value={status.execution.elevated ? 'Yes' : 'No'} />
              <KeyValue label="Windows" value={`${status.windows.displayVersion} (build ${status.windows.build}.${status.windows.revision})`} />
              <KeyValue label="Edition" value={status.windows.edition} />
              <KeyValue label="Session id" value={status.execution.sessionId !== null && status.execution.sessionId !== undefined ? formatNumber(status.execution.sessionId) : undefined} />
            </Section>
          </div>
        </>
      ) : null}
    </div>
  );
}
