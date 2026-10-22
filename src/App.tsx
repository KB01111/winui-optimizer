import { useMemo, useState, type ReactElement } from 'react';
import {
  Badge,
  Caption1,
  Tab,
  TabList,
  Text,
  makeStyles,
  tokens,
  type SelectTabData,
  type SelectTabEvent,
} from '@fluentui/react-components';
import {
  GridRegular,
  PulseRegular,
  SearchRegular,
  SettingsRegular,
  ShieldErrorRegular,
  SparkleRegular,
  VaultRegular,
} from '@fluentui/react-icons';
import { StatusPill } from './components/StatusPill';
import { summarizeProtection } from './lib/protection';
import { useLiveEvents } from './state/LiveEventsProvider';
import { useSystemStatus } from './state/SystemStatusProvider';
import { QuarantineProvider } from './state/QuarantineProvider';
import { AiIntelligencePage } from './pages/AiIntelligencePage';
import { LiveActivityPage } from './pages/LiveActivityPage';
import { OverviewPage } from './pages/OverviewPage';
import { QuarantinePage } from './pages/QuarantinePage';
import { ScanCenterPage } from './pages/ScanCenterPage';
import { SettingsPage } from './pages/SettingsPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';

export type PageKey = 'overview' | 'live' | 'threat' | 'scan' | 'quarantine' | 'ai' | 'settings';

const useStyles = makeStyles({
  root: {
    display: 'grid',
    gridTemplateColumns: '220px minmax(0, 1fr)',
    height: '100vh',
    overflow: 'hidden',
    backgroundColor: tokens.colorNeutralBackground1,
  },
  sidebar: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    padding: '16px 8px',
    borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
    backgroundColor: tokens.colorNeutralBackground2,
    minWidth: 0,
    overflowY: 'auto',
  },
  brandBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    padding: '0 8px 8px 8px',
  },
  content: {
    display: 'flex',
    flexDirection: 'column',
    minWidth: 0,
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '16px',
    padding: '12px 24px',
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    backgroundColor: tokens.colorNeutralBackground2,
    flexWrap: 'wrap',
  },
  headerMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  scrollArea: {
    flexGrow: 1,
    overflowY: 'auto',
    minHeight: 0,
  },
  badgeRow: {
    display: 'flex',
    gap: '4px',
    alignItems: 'center',
    flexWrap: 'wrap',
  },
  navIcon: {
    marginRight: '8px',
  },
});

const NAV_ITEMS: Array<{ key: PageKey; label: string; icon: ReactElement }> = [
  { key: 'overview', label: 'Overview', icon: <GridRegular /> },
  { key: 'live', label: 'Live activity', icon: <PulseRegular /> },
  { key: 'threat', label: 'Threat intelligence', icon: <ShieldErrorRegular /> },
  { key: 'scan', label: 'Scan center', icon: <SearchRegular /> },
  { key: 'quarantine', label: 'Quarantine', icon: <VaultRegular /> },
  { key: 'ai', label: 'AI intelligence', icon: <SparkleRegular /> },
  { key: 'settings', label: 'Settings', icon: <SettingsRegular /> },
];

function pageFor(key: PageKey) {
  switch (key) {
    case 'overview':
      return <OverviewPage />;
    case 'live':
      return <LiveActivityPage />;
    case 'threat':
      return <ThreatIntelligencePage />;
    case 'scan':
      return <ScanCenterPage />;
    case 'quarantine':
      return <QuarantinePage />;
    case 'ai':
      return <AiIntelligencePage />;
    case 'settings':
      return <SettingsPage />;
  }
}

export function App() {
  const styles = useStyles();
  const [page, setPage] = useState<PageKey>('overview');
  const { status, error: statusError } = useSystemStatus();
  const { connectionError } = useLiveEvents();

  const protection = useMemo(() => summarizeProtection(status), [status]);
  const engine = status?.engine;
  const engineRunning = typeof engine?.running === 'boolean' ? engine.running : null;
  const ai = status?.ai;
  const identity = status?.packageIdentity;

  const onTabSelect = (_event: SelectTabEvent, data: SelectTabData) => {
    setPage(data.value as PageKey);
  };

  return (
    <QuarantineProvider>
      <div className={styles.root}>
        <nav className={styles.sidebar} aria-label="Primary">
          <div className={styles.brandBlock}>
            <Text size={500} weight="semibold">
              AI Antivirus
            </Text>
            <Caption1>{status ? `v${status.version}` : 'Security dashboard'}</Caption1>
          </div>
          <TabList
            vertical
            selectedValue={page}
            onTabSelect={onTabSelect}
            aria-label="Dashboard sections"
            size="small"
          >
            {NAV_ITEMS.map((item) => (
              <Tab key={item.key} value={item.key} icon={item.icon}>
                {item.label}
              </Tab>
            ))}
          </TabList>
        </nav>

        <div className={styles.content}>
          <header className={styles.header}>
            <div className={styles.headerMeta}>
              <Text size={400} weight="semibold">
                {status?.productName ?? 'AI Antivirus'}
              </Text>
              <div className={styles.badgeRow}>
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
                />
                <StatusPill
                  label={
                    engineRunning === null
                      ? 'Engine unknown'
                      : engineRunning
                        ? 'Engine running'
                        : 'Engine stopped'
                  }
                  tone={engineRunning === null ? 'subtle' : engineRunning ? 'success' : 'danger'}
                />
                <StatusPill
                  label={
                    ai
                      ? ai.mode === 'offline'
                        ? 'AI offline'
                        : ai.configured
                          ? `AI ${ai.mode}`
                          : `AI ${ai.mode} (unconfigured)`
                      : 'AI unknown'
                  }
                  tone={ai ? (ai.mode === 'offline' ? 'subtle' : ai.configured ? 'brand' : 'warning') : 'subtle'}
                />
                {connectionError ? <StatusPill label="Live feed disconnected" tone="danger" /> : null}
                {statusError && status ? <StatusPill label="Status stale" tone="warning" /> : null}
              </div>
            </div>
            <div className={styles.badgeRow}>
              {identity ? (
                <Badge appearance="tint" color={identity.available ? 'informative' : 'subtle'} title={identity.fullName ?? undefined}>
                  {identity.available ? `MSIX · ${identity.familyName ?? 'packaged'}` : 'Unpackaged build'}
                </Badge>
              ) : (
                <Badge appearance="tint" color="subtle">
                  Package identity unknown
                </Badge>
              )}
            </div>
          </header>

          <main className={styles.scrollArea}>{pageFor(page)}</main>
        </div>
      </div>
    </QuarantineProvider>
  );
}
