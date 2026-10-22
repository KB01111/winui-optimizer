import { useCallback, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Caption1,
  Divider,
  MessageBar,
  MessageBarBody,
  Radio,
  RadioGroup,
  Spinner,
  Text,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import { BeakerRegular, CheckmarkCircleRegular, ErrorCircleRegular } from '@fluentui/react-icons';
import { configureAi, getSettings, listEvents, testAiProvider, updateSettings } from '../api/commands';
import type { AiConfigInput, AiMode, ProviderTestResult } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBanner } from '../components/ErrorBanner';
import { KeyValue } from '../components/KeyValue';
import { Metric } from '../components/Metric';
import { Section } from '../components/Section';
import { StatusPill } from '../components/StatusPill';
import { useAsyncResource } from '../hooks/useAsyncResource';
import { useNow } from '../hooks/useNow';
import { describeError } from '../lib/errors';
import {
  formatBytes,
  formatNumber,
  formatProbability,
  formatTimestamp,
  formatUptime,
  formatUsd,
} from '../lib/format';
import { mergeSettings } from '../lib/settings';
import { PROVIDER_STATUS_LABELS, kindLabel, providerStatusTone } from '../lib/severity';
import { useSystemStatus } from '../state/SystemStatusProvider';
import { useSharedStyles } from '../styles/shared';

const useStyles = makeStyles({
  modeRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
    flexWrap: 'wrap',
  },
  providerGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
    gap: '16px',
  },
  providerCard: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
    padding: '12px',
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  providerHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  historyRow: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    padding: '6px 0',
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
    ':last-child': { borderBottom: 'none' },
  },
  historyMeta: {
    display: 'flex',
    gap: '8px',
    color: tokens.colorNeutralForeground3,
    flexWrap: 'wrap',
  },
  metrics: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    gap: '16px',
  },
  muted: {
    color: tokens.colorNeutralForeground3,
  },
});

const MODE_OPTIONS: Array<{ value: AiMode; label: string; hint: string }> = [
  { value: 'offline', label: 'Offline', hint: 'No network calls; the engine uses deterministic rules only.' },
  { value: 'cloud', label: 'Cloud', hint: 'Cloud decision models are used for advisory classification.' },
  { value: 'hybrid', label: 'Hybrid', hint: 'Local models first; cloud escalation when uncertain.' },
];

export function AiIntelligencePage() {
  const styles = useStyles();
  const shared = useSharedStyles();
  const { status, refresh } = useSystemStatus();
  const ai = status?.ai;
  const hardware = status?.hardware;
  const now = useNow(30_000);

  const [savingMode, setSavingMode] = useState(false);
  const [modeError, setModeError] = useState<string | null>(null);
  const [testingModel, setTestingModel] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, ProviderTestResult>>({});
  const [testError, setTestError] = useState<string | null>(null);

  const history = useAsyncResource(
    async () => {
      const page = await listEvents({ limit: 20, offset: 0, kind: 'ai_decision' });
      return page.items ?? [];
    },
    [],
    60_000,
  );

  const providers = useMemo(() => ai?.providers ?? [], [ai]);

  const changeMode = useCallback(
    async (mode: AiMode) => {
      if (!ai || ai.mode === mode) {
        return;
      }
      setSavingMode(true);
      setModeError(null);
      try {
        // `configure_ai` requires the full config. Read the persisted limits so
        // a mode switch does not silently reset the operator's other values.
        // The API key is intentionally omitted: the stored credential is never
        // re-sent from the dashboard.
        const persisted = mergeSettings(await getSettings());
        const config: AiConfigInput = {
          mode,
          primaryModel: ai.primaryModel || persisted.ai.primaryModel,
          escalationModel: ai.escalationModel || persisted.ai.escalationModel,
          timeoutMs: persisted.ai.timeoutMs,
          requestsPerMinute: persisted.ai.requestsPerMinute,
          dailyCostLimitUsd: persisted.ai.dailyCostLimitUsd,
          allowCloudState: ai.allowCloudState,
          clearApiKey: false,
        };
        await configureAi(config);
        await updateSettings({ ai: { ...persisted.ai, mode } });
        await refresh();
      } catch (error) {
        setModeError(describeError(error));
      } finally {
        setSavingMode(false);
      }
    },
    [ai, refresh],
  );

  const runProviderTest = useCallback(
    async (model: string) => {
      setTestingModel(model);
      setTestError(null);
      try {
        const result = await testAiProvider(model);
        setTestResults((previous) => ({ ...previous, [model]: result }));
      } catch (error) {
        setTestError(describeError(error));
      } finally {
        setTestingModel(null);
      }
    },
    [],
  );

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            AI intelligence
          </Text>
          <Caption1 className={shared.muted}>
            Decision-provider routing is advisory. The deterministic policy engine always decides outcomes.
          </Caption1>
        </div>
        {ai ? (
          <StatusPill
            label={ai.mode === 'offline' ? 'Offline mode' : `${ai.mode} mode`}
            tone={ai.mode === 'offline' ? 'subtle' : 'brand'}
          />
        ) : null}
      </div>

      {!ai ? (
        <EmptyState
          title="AI status unavailable"
          description="The engine has not reported AI provider state yet. The engine remains fully functional without AI."
        />
      ) : (
        <>
          <Section title="Mode" subtitle="Choose how classification requests are routed">
            {modeError ? <ErrorBanner title="Could not change mode" message={modeError} /> : null}
            <div className={styles.modeRow}>
              <RadioGroup
                layout="horizontal"
                value={ai.mode}
                onChange={(_, data) => void changeMode(data.value as AiMode)}
                disabled={savingMode}
              >
                {MODE_OPTIONS.map((option) => (
                  <Radio key={option.value} value={option.value} label={option.label} />
                ))}
              </RadioGroup>
              {savingMode ? <Spinner size="tiny" label="Applying…" /> : null}
            </div>
            <Caption1 className={styles.muted}>
              {MODE_OPTIONS.find((option) => option.value === ai.mode)?.hint ?? 'Unknown mode.'}
            </Caption1>
            <Divider />
            <div className={styles.metrics}>
              <Metric label="Primary model" value={ai.primaryModel || '—'} hint="Deterministic routing first" />
              <Metric label="Escalation model" value={ai.escalationModel || '—'} hint="Used when the primary is uncertain" />
              <Metric
                label="Requests"
                value={formatNumber(ai.requests)}
                hint={`${formatNumber(ai.failures)} failure(s)`}
              />
              <Metric
                label="Total cost"
                value={formatUsd(ai.totalCostUsd)}
                hint="Sum reported by provider health"
              />
            </div>
            <KeyValue label="Cloud state sharing" value={ai.allowCloudState ? 'Allowed (redacted)' : 'Disabled'} />
            <KeyValue label="Offline capable" value={ai.offlineCapable ? 'Yes' : 'No'} />
            <KeyValue
              label="Average latency"
              value={
                ai.avgLatencyMs !== null && ai.avgLatencyMs !== undefined
                  ? `${formatNumber(ai.avgLatencyMs)} ms`
                  : undefined
              }
            />
            <KeyValue label="Last request" value={formatTimestamp(ai.lastRequestAtMs)} />
            <KeyValue
              label="Local route"
              value={`${ai.local.route.primary} (fallback ${ai.local.route.fallback})`}
            />
            <KeyValue
              label="Local model"
              value={`${ai.local.model.name} · ${ai.local.model.runtime}`}
              mono
            />
            <KeyValue label="Local model available" value={ai.local.model.available ? 'Yes' : 'No'} />
            <Caption1 className={styles.muted}>{ai.local.route.reason}</Caption1>
            {ai.local.model.note ? <Caption1 className={styles.muted}>{ai.local.model.note}</Caption1> : null}
          </Section>

          <Section
            title="Providers"
            subtitle="Health is reported by the engine's provider router"
            action={
              ai.primaryModel ? (
                <Button
                  appearance="secondary"
                  icon={<BeakerRegular />}
                  disabled={testingModel !== null}
                  onClick={() => void runProviderTest(ai.primaryModel)}
                >
                  Test primary model
                </Button>
              ) : undefined
            }
          >
            {testError ? <ErrorBanner title="Provider test failed" message={testError} /> : null}
            {providers.length === 0 ? (
              <EmptyState
                title="No providers configured"
                description="The engine classifies with deterministic rules only. Configure a provider in Settings to enable advisory AI."
              />
            ) : (
              <div className={styles.providerGrid}>
                {providers.map((provider) => {
                  const test = testResults[provider.model];
                  return (
                    <div key={`${provider.provider}-${provider.model}`} className={styles.providerCard}>
                      <div className={styles.providerHeader}>
                        <Text weight="semibold">{provider.provider}</Text>
                        <Badge appearance="tint" color={providerStatusTone(provider.status)} size="small">
                          {PROVIDER_STATUS_LABELS[provider.status] ?? provider.status}
                        </Badge>
                      </div>
                      <KeyValue label="Model" value={provider.model} mono />
                      <KeyValue label="Requests" value={formatNumber(provider.requests)} />
                      <KeyValue label="Failures" value={formatNumber(provider.failures)} />
                      <KeyValue
                        label="Last latency"
                        value={provider.lastLatencyMs !== null && provider.lastLatencyMs !== undefined ? `${formatNumber(provider.lastLatencyMs)} ms` : undefined}
                      />
                      <KeyValue label="Total cost" value={formatUsd(provider.totalCostUsd)} />
                      <KeyValue label="Checked" value={formatTimestamp(provider.checkedAtMs)} />
                      {provider.lastError ? (
                        <MessageBar intent="warning">
                          <MessageBarBody>{provider.lastError}</MessageBarBody>
                        </MessageBar>
                      ) : null}
                      <div className={shared.toolbar}>
                        <Button
                          size="small"
                          appearance="secondary"
                          icon={<BeakerRegular />}
                          disabled={testingModel !== null}
                          onClick={() => void runProviderTest(provider.model)}
                        >
                          {testingModel === provider.model ? 'Testing…' : 'Test provider'}
                        </Button>
                      </div>
                      {test ? (
                        <MessageBar intent={test.ok ? 'success' : 'error'}>
                          <MessageBarBody>
                            <div className={styles.providerHeader}>
                              {test.ok ? <CheckmarkCircleRegular /> : <ErrorCircleRegular />}
                              <Text weight="semibold">
                                {test.ok ? 'Provider responded' : 'Provider test failed'}
                              </Text>
                              <Caption1>{`${formatNumber(test.latencyMs)} ms`}</Caption1>
                            </div>
                            {test.category ? <Caption1>{`Category: ${test.category}`}</Caption1> : null}
                            {test.confidence !== null && test.confidence !== undefined ? (
                              <Caption1>{`Confidence: ${formatProbability(test.confidence)}`}</Caption1>
                            ) : null}
                            {test.costUsd !== null && test.costUsd !== undefined ? (
                              <Caption1>{`Cost: ${formatUsd(test.costUsd)}`}</Caption1>
                            ) : null}
                            {test.error ? <Caption1>{test.error}</Caption1> : null}
                          </MessageBarBody>
                        </MessageBar>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </Section>

          <Section
            title="Local routing and hardware"
            subtitle="The engine picks the on-device runtime; the dashboard shows the detected hardware it routes on"
          >
            <div className={styles.metrics}>
              <Metric
                label="Primary runtime"
                value={ai.local.route.primary}
                hint={`Fallback ${ai.local.route.fallback}`}
              />
              <Metric
                label="Local model"
                value={ai.local.model.name}
                hint={ai.local.model.runtime}
                tone={ai.local.model.available ? 'good' : 'warn'}
              />
              <Metric
                label="Discrete GPU"
                value={ai.local.route.allowDiscreteGpu ? 'On demand' : 'Not allowed'}
                hint="Routine background analysis never uses a dGPU"
              />
            </div>
            <Caption1 className={styles.muted}>{ai.local.route.reason}</Caption1>
            {ai.local.model.note ? <Caption1 className={styles.muted}>{ai.local.model.note}</Caption1> : null}
            <Divider />
            {hardware ? (
              <>
                <div className={styles.metrics}>
                  <Metric
                    label="CPU"
                    value={hardware.cpuName ?? hardware.cpuArch}
                    hint={`${formatNumber(hardware.logicalCores)} logical cores${hardware.physicalCores ? ` · ${formatNumber(hardware.physicalCores)} physical` : ''}`}
                  />
                  <Metric
                    label="Memory available"
                    value={formatBytes(hardware.availableRamMb * 1024 * 1024, 0)}
                    hint={`of ${formatBytes(hardware.totalRamMb * 1024 * 1024, 0)}`}
                  />
                  <Metric
                    label="Power"
                    value={hardware.battery.present ? (hardware.battery.acOnline ? 'AC power' : 'On battery') : 'No battery reported'}
                    hint={hardware.battery.present && hardware.battery.percent !== null && hardware.battery.percent !== undefined ? `${hardware.battery.percent}% charge` : undefined}
                    tone={hardware.battery.present && !hardware.battery.acOnline ? 'warn' : 'neutral'}
                  />
                </div>
                <Divider />
                <KeyValue
                  label="GPUs"
                  value={
                    hardware.gpus.length === 0
                      ? 'None reported'
                      : hardware.gpus
                          .map((gpu) => `${gpu.name}${gpu.isDiscrete ? ' (discrete)' : ''}${gpu.isSoftware ? ' (software)' : ''}`)
                          .join(', ')
                  }
                />
                <KeyValue
                  label="NPU"
                  value={hardware.npu ? `${hardware.npu.name}${hardware.npu.available ? '' : ' (runtime not validated)'}` : 'Not reported'}
                />
                <Caption1 className={styles.muted}>
                  On battery power the engine never routes routine background analysis to a discrete GPU, and an NPU is
                  only selected when a validated compatible runtime is present.
                </Caption1>
              </>
            ) : (
              <EmptyState title="Hardware profile unavailable" description="The engine has not reported a hardware profile yet." />
            )}
          </Section>

          <Section
            title="Classification history"
            subtitle="Recent AI decision events recorded by the engine"
            action={
              <Button appearance="subtle" onClick={history.reload} disabled={history.loading}>
                Refresh
              </Button>
            }
          >
            {history.error ? <ErrorBanner title="Could not load classification history" message={history.error} onRetry={history.reload} /> : null}
            {history.loading && history.data === null ? <Spinner size="tiny" label="Loading history…" /> : null}
            {!history.loading && !history.error && (history.data?.length ?? 0) === 0 ? (
              <EmptyState
                title="No AI decisions recorded"
                description="Decisions appear here after the engine routes an event to a decision provider."
              />
            ) : null}
            {(history.data ?? []).map((event) => (
              <div key={event.id} className={styles.historyRow}>
                <div className={styles.providerHeader}>
                  <Text weight="semibold">{event.title || kindLabel(event.kind)}</Text>
                  {event.assessment ? <Caption1 className={styles.muted}>{`deterministic score ${event.assessment.score.toFixed(1)}`}</Caption1> : null}
                </div>
                {event.description ? <Caption1>{event.description}</Caption1> : null}
                <div className={styles.historyMeta}>
                  <Caption1>{formatTimestamp(event.timestampMs)}</Caption1>
                  {event.process?.name ? <Caption1>{event.process.name}</Caption1> : null}
                  {event.file?.name ? <Caption1>{event.file.name}</Caption1> : null}
                  {event.process?.startedAtMs ? <Caption1>{`process up ${formatUptime((now - event.process.startedAtMs) / 1000)}`}</Caption1> : null}
                </div>
              </div>
            ))}
          </Section>
        </>
      )}
    </div>
  );
}
