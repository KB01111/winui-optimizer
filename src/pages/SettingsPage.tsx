import { useCallback, useEffect, useState } from 'react';
import {
  Button,
  Caption1,
  Divider,
  Dropdown,
  Input,
  MessageBar,
  MessageBarBody,
  Option,
  Spinner,
  Switch,
  Text,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import {
  AddRegular,
  DeleteRegular,
  SaveRegular,
  SendRegular,
} from '@fluentui/react-icons';
import {
  configureAi,
  describeNotificationOutcome,
  getSettings,
  sendTestNotification,
  updateSettings,
} from '../api/commands';
import type { AiConfigInput, AiMode, NotificationOutcome } from '../api/types';
import { ErrorBanner } from '../components/ErrorBanner';
import { EmptyState } from '../components/EmptyState';
import { KeyValue } from '../components/KeyValue';
import { Section } from '../components/Section';
import { StatusPill } from '../components/StatusPill';
import { useAsyncResource } from '../hooks/useAsyncResource';
import { describeError } from '../lib/errors';
import { formatNumber, timestamp as nowStamp } from '../lib/format';
import {
  DEFAULT_SETTINGS,
  mergeSettings,
  type AiSettings,
  type AppSettings,
  type PrivacySettings,
} from '../lib/settings';
import { useSystemStatus } from '../state/SystemStatusProvider';
import { useSharedStyles } from '../styles/shared';

const useStyles = makeStyles({
  formGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '12px',
    alignItems: 'end',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  },
  fieldLabel: {
    color: tokens.colorNeutralForeground3,
  },
  exclusionRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '4px 0',
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
  },
  exclusionPath: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    flexGrow: 1,
    overflowWrap: 'anywhere',
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  switchRow: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '16px',
    padding: '6px 0',
  },
  switchText: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    maxWidth: '640px',
  },
  muted: {
    color: tokens.colorNeutralForeground3,
  },
  saveRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
});

interface PolicyForm {
  autoQuarantineEnabled: boolean;
  autoQuarantineRequiresKnownHash: boolean;
  autoQuarantineMinScore: string;
  investigateMinScore: string;
  alertMinScore: string;
}

function toPolicyForm(settings: AppSettings): PolicyForm {
  return {
    autoQuarantineEnabled: settings.policy.autoQuarantineEnabled,
    autoQuarantineRequiresKnownHash: settings.policy.autoQuarantineRequiresKnownHash,
    autoQuarantineMinScore: String(settings.policy.autoQuarantineMinScore),
    investigateMinScore: String(settings.policy.investigateMinScore),
    alertMinScore: String(settings.policy.alertMinScore),
  };
}

function parseNumber(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

const AI_MODES: Array<{ value: AiMode; label: string }> = [
  { value: 'offline', label: 'Offline' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'hybrid', label: 'Hybrid' },
];

export function SettingsPage() {
  const styles = useStyles();
  const shared = useSharedStyles();
  const { refresh: refreshStatus } = useSystemStatus();

  const settings = useAsyncResource<AppSettings>(async () => mergeSettings(await getSettings()), []);

  const [policy, setPolicy] = useState<PolicyForm>(() => toPolicyForm(DEFAULT_SETTINGS));
  const [exclusions, setExclusions] = useState<string[]>([]);
  const [exclusionDraft, setExclusionDraft] = useState('');
  const [privacy, setPrivacy] = useState<PrivacySettings>(DEFAULT_SETTINGS.privacy);
  const [aiForm, setAiForm] = useState<AiSettings>(DEFAULT_SETTINGS.ai);
  const [apiKeyDraft, setApiKeyDraft] = useState('');
  const [clearApiKey, setClearApiKey] = useState(false);

  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [notificationOutcome, setNotificationOutcome] = useState<NotificationOutcome | null>(null);
  const [notificationError, setNotificationError] = useState<string | null>(null);
  const [testingNotification, setTestingNotification] = useState(false);

  const reloadSettings = settings.reload;

  useEffect(() => {
    if (!settings.data) {
      return;
    }
    setPolicy(toPolicyForm(settings.data));
    setExclusions(settings.data.scanner.exclusions);
    setPrivacy(settings.data.privacy);
    setAiForm(settings.data.ai);
  }, [settings.data]);

  const applyPatch = useCallback(
    async (key: string, patch: Record<string, unknown>, successText: string) => {
      setSavingKey(key);
      setSaveError(null);
      setSavedMessage(null);
      try {
        await updateSettings(patch);
        setSavedMessage(`${successText} · ${nowStamp()}`);
        reloadSettings();
      } catch (error) {
        setSaveError(describeError(error));
        throw error;
      } finally {
        setSavingKey(null);
      }
    },
    [reloadSettings],
  );

  const savePolicy = useCallback(async () => {
    const patch = {
      policy: {
        autoQuarantineEnabled: policy.autoQuarantineEnabled,
        autoQuarantineRequiresKnownHash: policy.autoQuarantineRequiresKnownHash,
        autoQuarantineMinScore: parseNumber(
          policy.autoQuarantineMinScore,
          DEFAULT_SETTINGS.policy.autoQuarantineMinScore,
        ),
        investigateMinScore: parseNumber(policy.investigateMinScore, DEFAULT_SETTINGS.policy.investigateMinScore),
        alertMinScore: parseNumber(policy.alertMinScore, DEFAULT_SETTINGS.policy.alertMinScore),
      },
    };
    try {
      await applyPatch('policy', patch, 'Policy thresholds saved');
    } catch {
      // error already surfaced
    }
  }, [applyPatch, policy]);

  const saveExclusions = useCallback(
    async (next: string[]) => {
      try {
        await applyPatch('scanner', { scanner: { exclusions: next } }, 'Scan exclusions saved');
      } catch {
        // error already surfaced
      }
    },
    [applyPatch],
  );

  const toggleNotifications = useCallback(
    async (checked: boolean) => {
      const previous = privacy;
      setPrivacy((current) => ({ ...current, notificationsEnabled: checked }));
      try {
        await applyPatch(
          'notifications',
          { privacy: { notificationsEnabled: checked } },
          'Notification preference saved',
        );
      } catch {
        setPrivacy(previous);
      }
    },
    [applyPatch, privacy],
  );

  const changePrivacy = useCallback(
    async (key: 'cloudAiEnabled' | 'storeRawPaths' | 'telemetryLocalOnly', checked: boolean) => {
      const previous = privacy;
      const next = { ...privacy, [key]: checked };
      setPrivacy(next);
      try {
        await applyPatch('privacy', { privacy: { [key]: checked } }, 'Privacy settings saved');
      } catch {
        setPrivacy(previous);
      }
    },
    [applyPatch, privacy],
  );

  const saveAi = useCallback(async () => {
    const config: AiConfigInput = {
      mode: aiForm.mode,
      primaryModel: aiForm.primaryModel,
      escalationModel: aiForm.escalationModel,
      timeoutMs: aiForm.timeoutMs,
      requestsPerMinute: aiForm.requestsPerMinute,
      dailyCostLimitUsd: aiForm.dailyCostLimitUsd,
      allowCloudState: aiForm.allowCloudState,
      clearApiKey,
    };
    const trimmedKey = apiKeyDraft.trim();
    if (trimmedKey.length > 0) {
      // Write-only: the key is sent once and never displayed back.
      config.apiKey = trimmedKey;
    }
    setSavingKey('ai');
    setSaveError(null);
    setSavedMessage(null);
    try {
      await configureAi(config);
      // Keep the settings document in sync with the configuration form so a
      // later mode switch or reload reads the same limits (get_settings does
      // not expose the encrypted AI service config).
      await updateSettings({ ai: { ...aiForm } });
      setApiKeyDraft('');
      setClearApiKey(false);
      setSavedMessage(`AI provider configuration saved · ${nowStamp()}`);
      await refreshStatus();
      reloadSettings();
    } catch (error) {
      setSaveError(describeError(error));
    } finally {
      setSavingKey(null);
    }
  }, [aiForm, apiKeyDraft, clearApiKey, refreshStatus, reloadSettings]);

  const runNotificationTest = useCallback(async () => {
    setTestingNotification(true);
    setNotificationError(null);
    setNotificationOutcome(null);
    try {
      const outcome = await sendTestNotification();
      setNotificationOutcome(outcome);
    } catch (error) {
      setNotificationError(describeError(error));
    } finally {
      setTestingNotification(false);
    }
  }, []);

  const addExclusion = useCallback(() => {
    const trimmed = exclusionDraft.trim();
    if (!trimmed || exclusions.includes(trimmed)) {
      return;
    }
    const next = [...exclusions, trimmed];
    setExclusions(next);
    setExclusionDraft('');
    void saveExclusions(next);
  }, [exclusionDraft, exclusions, saveExclusions]);

  const removeExclusion = useCallback(
    (path: string) => {
      const next = exclusions.filter((item) => item !== path);
      setExclusions(next);
      void saveExclusions(next);
    },
    [exclusions, saveExclusions],
  );

  const notificationTone =
    notificationOutcome === null
      ? null
      : notificationOutcome === 'sent'
        ? 'success'
        : notificationOutcome === 'no_package_identity' || notificationOutcome === 'unsupported'
          ? 'warning'
          : 'error';

  return (
    <div className={shared.page}>
      <div className={shared.pageHeader}>
        <div className={shared.pageTitleBlock}>
          <Text size={700} weight="semibold">
            Settings
          </Text>
          <Caption1 className={shared.muted}>
            Policy thresholds, exclusions, notifications, AI provider and privacy controls.
          </Caption1>
        </div>
        {settings.loading ? <Spinner size="tiny" label="Loading settings…" /> : null}
      </div>

      {settings.error ? (
        <ErrorBanner title="Could not load settings" message={settings.error} onRetry={settings.reload} />
      ) : null}
      {saveError ? <ErrorBanner title="Could not save settings" message={saveError} /> : null}
      {savedMessage ? (
        <MessageBar intent="success">
          <MessageBarBody>{savedMessage}</MessageBarBody>
        </MessageBar>
      ) : null}

      {settings.data ? (
        <>
          <Section
            title="Policy thresholds"
            subtitle="Evaluated by the deterministic Rust policy engine for every event and scan"
            action={
              <Button
                appearance="primary"
                icon={<SaveRegular />}
                onClick={() => void savePolicy()}
                disabled={savingKey === 'policy'}
              >
                {savingKey === 'policy' ? 'Saving…' : 'Save thresholds'}
              </Button>
            }
          >
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Auto-quarantine confirmed threats</Text>
                <Caption1 className={styles.muted}>
                  Off by default. When enabled, the deterministic policy engine may quarantine only when its configured
                  rules match. AI output can never trigger quarantine.
                </Caption1>
              </div>
              <Switch
                checked={policy.autoQuarantineEnabled}
                onChange={(_, data) =>
                  setPolicy((previous) => ({ ...previous, autoQuarantineEnabled: data.checked }))
                }
                label="Auto-quarantine"
                labelPosition="before"
              />
            </div>
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Require a known-malware hash</Text>
                <Caption1 className={styles.muted}>
                  Auto-quarantine additionally requires a SHA-256 match against a known malicious sample identifier.
                </Caption1>
              </div>
              <Switch
                checked={policy.autoQuarantineRequiresKnownHash}
                onChange={(_, data) =>
                  setPolicy((previous) => ({ ...previous, autoQuarantineRequiresKnownHash: data.checked }))
                }
                label="Require known hash"
                labelPosition="before"
              />
            </div>
            <Divider />
            <div className={styles.formGrid}>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Investigate from score</Caption1>
                <Input
                  type="number"
                  value={policy.investigateMinScore}
                  onChange={(_, data) => setPolicy((previous) => ({ ...previous, investigateMinScore: data.value }))}
                />
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Alert from score</Caption1>
                <Input
                  type="number"
                  value={policy.alertMinScore}
                  onChange={(_, data) => setPolicy((previous) => ({ ...previous, alertMinScore: data.value }))}
                />
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Auto-quarantine from score</Caption1>
                <Input
                  type="number"
                  value={policy.autoQuarantineMinScore}
                  onChange={(_, data) =>
                    setPolicy((previous) => ({ ...previous, autoQuarantineMinScore: data.value }))
                  }
                />
              </div>
            </div>
          </Section>

          <Section
            title="Scan exclusions"
            subtitle="Stored under scanner.exclusions; excluded paths and their subtrees are skipped by the scanner"
          >
            {exclusions.length === 0 ? (
              <EmptyState title="No exclusions configured" description="Every path is eligible for scanning." />
            ) : (
              exclusions.map((path) => (
                <div key={path} className={styles.exclusionRow}>
                  <span className={styles.exclusionPath}>{path}</span>
                  <Button
                    size="small"
                    appearance="subtle"
                    icon={<DeleteRegular />}
                    onClick={() => removeExclusion(path)}
                    aria-label={`Remove exclusion ${path}`}
                  />
                </div>
              ))
            )}
            <div className={styles.row}>
              <Input
                style={{ minWidth: '280px', flexGrow: 1 }}
                placeholder="C:\\Tools\\trusted"
                value={exclusionDraft}
                onChange={(_, data) => setExclusionDraft(data.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    addExclusion();
                  }
                }}
              />
              <Button
                appearance="secondary"
                icon={<AddRegular />}
                onClick={addExclusion}
                disabled={exclusionDraft.trim().length === 0}
              >
                Add exclusion
              </Button>
            </div>
          </Section>

          <Section title="Notifications" subtitle="Windows toast notifications for high-severity alerts">
            {notificationError ? <ErrorBanner title="Test notification failed" message={notificationError} /> : null}
            {notificationOutcome && notificationTone ? (
              <MessageBar intent={notificationTone}>
                <MessageBarBody>{describeNotificationOutcome(notificationOutcome)}</MessageBarBody>
              </MessageBar>
            ) : null}
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Enable notifications</Text>
                <Caption1 className={styles.muted}>
                  Notifications require package identity (MSIX). Unpackaged builds report that instead of failing
                  silently.
                </Caption1>
              </div>
              <Switch
                checked={privacy.notificationsEnabled}
                onChange={(_, data) => void toggleNotifications(data.checked)}
                label="Notifications"
                labelPosition="before"
                disabled={savingKey === 'notifications'}
              />
            </div>
            <div className={styles.row}>
              <Button
                appearance="secondary"
                icon={<SendRegular />}
                onClick={() => void runNotificationTest()}
                disabled={testingNotification}
              >
                {testingNotification ? 'Sending…' : 'Send test notification'}
              </Button>
            </div>
          </Section>

          <Section
            title="AI provider"
            subtitle="API keys are write-only: they are never displayed back by the dashboard"
            action={
              <Button
                appearance="primary"
                icon={<SaveRegular />}
                onClick={() => void saveAi()}
                disabled={savingKey === 'ai'}
              >
                {savingKey === 'ai' ? 'Saving…' : 'Save AI configuration'}
              </Button>
            }
          >
            <div className={styles.formGrid}>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Mode</Caption1>
                <Dropdown
                  value={AI_MODES.find((mode) => mode.value === aiForm.mode)?.label ?? 'Offline'}
                  selectedOptions={[aiForm.mode]}
                  onOptionSelect={(_, data) => {
                    const value = data.optionValue as AiMode;
                    setAiForm((previous) => ({ ...previous, mode: value }));
                  }}
                >
                  {AI_MODES.map((mode) => (
                    <Option key={mode.value} value={mode.value} text={mode.label}>
                      {mode.label}
                    </Option>
                  ))}
                </Dropdown>
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Primary model</Caption1>
                <Input
                  value={aiForm.primaryModel}
                  placeholder="inception/mercury-decide"
                  onChange={(_, data) => setAiForm((previous) => ({ ...previous, primaryModel: data.value }))}
                />
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Escalation model</Caption1>
                <Input
                  value={aiForm.escalationModel}
                  placeholder="typesafe/jev-1.14"
                  onChange={(_, data) => setAiForm((previous) => ({ ...previous, escalationModel: data.value }))}
                />
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>API key (write-only)</Caption1>
                <Input
                  type="password"
                  value={apiKeyDraft}
                  placeholder="Enter a new key to replace the stored one"
                  autoComplete="off"
                  onChange={(_, data) => setApiKeyDraft(data.value)}
                />
                <Caption1 className={styles.muted}>
                  The stored key is never sent back to the dashboard or shown in this field.
                </Caption1>
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Timeout (ms)</Caption1>
                <Input
                  type="number"
                  value={String(aiForm.timeoutMs)}
                  onChange={(_, data) =>
                    setAiForm((previous) => ({ ...previous, timeoutMs: parseNumber(data.value, previous.timeoutMs) }))
                  }
                />
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Requests per minute</Caption1>
                <Input
                  type="number"
                  value={String(aiForm.requestsPerMinute)}
                  onChange={(_, data) =>
                    setAiForm((previous) => ({
                      ...previous,
                      requestsPerMinute: parseNumber(data.value, previous.requestsPerMinute),
                    }))
                  }
                />
              </div>
              <div className={styles.field}>
                <Caption1 className={styles.fieldLabel}>Daily cost limit (USD)</Caption1>
                <Input
                  type="number"
                  value={String(aiForm.dailyCostLimitUsd)}
                  onChange={(_, data) =>
                    setAiForm((previous) => ({
                      ...previous,
                      dailyCostLimitUsd: parseNumber(data.value, previous.dailyCostLimitUsd),
                    }))
                  }
                />
              </div>
            </div>
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Clear the stored API key</Text>
                <Caption1 className={styles.muted}>
                  Deletes the DPAPI-protected credential. Cloud and hybrid modes fail closed until a new key is saved.
                </Caption1>
              </div>
              <Switch
                checked={clearApiKey}
                onChange={(_, data) => setClearApiKey(data.checked)}
                label="Clear stored key"
                labelPosition="before"
              />
            </div>
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Allow cloud state sharing</Text>
                <Caption1 className={styles.muted}>
                  Off by default. Even when enabled, redaction removes usernames, absolute paths, command lines and full
                  hashes before anything leaves the machine.
                </Caption1>
              </div>
              <Switch
                checked={aiForm.allowCloudState}
                onChange={(_, data) => setAiForm((previous) => ({ ...previous, allowCloudState: data.checked }))}
                label="Cloud state sharing"
                labelPosition="before"
              />
            </div>
          </Section>

          <Section title="Privacy" subtitle="Defaults are local-only; nothing is shared unless explicitly enabled">
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Cloud AI classification</Text>
                <Caption1 className={styles.muted}>Master switch for any cloud decision provider usage.</Caption1>
              </div>
              <Switch
                checked={privacy.cloudAiEnabled}
                onChange={(_, data) => void changePrivacy('cloudAiEnabled', data.checked)}
                label="Cloud AI"
                labelPosition="before"
                disabled={savingKey === 'privacy'}
              />
            </div>
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Store raw file paths</Text>
                <Caption1 className={styles.muted}>
                  The desktop backend default is on. Turn this off to keep only redacted paths in stored events.
                </Caption1>
              </div>
              <Switch
                checked={privacy.storeRawPaths}
                onChange={(_, data) => void changePrivacy('storeRawPaths', data.checked)}
                label="Store raw paths"
                labelPosition="before"
                disabled={savingKey === 'privacy'}
              />
            </div>
            <div className={styles.switchRow}>
              <div className={styles.switchText}>
                <Text weight="semibold">Telemetry stays local</Text>
                <Caption1 className={styles.muted}>
                  Event data never leaves the machine; only AI classification requests can use the network.
                </Caption1>
              </div>
              <Switch
                checked={privacy.telemetryLocalOnly}
                onChange={(_, data) => void changePrivacy('telemetryLocalOnly', data.checked)}
                label="Local telemetry"
                labelPosition="before"
                disabled={savingKey === 'privacy'}
              />
            </div>
            <Divider />
            <div className={styles.row}>
              <StatusPill
                label={privacy.cloudAiEnabled ? 'Cloud AI enabled' : 'Cloud AI disabled'}
                tone={privacy.cloudAiEnabled ? 'warning' : 'success'}
              />
              <StatusPill
                label={privacy.storeRawPaths ? 'Raw paths stored' : 'Paths redacted'}
                tone={privacy.storeRawPaths ? 'warning' : 'success'}
              />
              <StatusPill
                label={privacy.telemetryLocalOnly ? 'Telemetry local' : 'Telemetry may leave the device'}
                tone={privacy.telemetryLocalOnly ? 'success' : 'danger'}
              />
            </div>
          </Section>

          <Section title="Data retention" subtitle="Configured in the backend settings document">
            <KeyValue
              label="Event retention"
              value={`${formatNumber(settings.data.engine.eventRetentionDays)} day(s)`}
            />
            <KeyValue
              label="Engine poll interval"
              value={`${formatNumber(settings.data.engine.pollIntervalMs)} ms`}
            />
            <MessageBar intent="info">
              <MessageBarBody>
                The desktop backend does not expose a purge command, so the dashboard cannot delete stored events.
                Quarantined files are only removed by an explicit user action.
              </MessageBarBody>
            </MessageBar>
          </Section>
        </>
      ) : null}
    </div>
  );
}
