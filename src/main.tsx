import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { FluentProvider, webDarkTheme, webLightTheme, type Theme } from '@fluentui/react-components';
import { App } from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LiveEventsProvider } from './state/LiveEventsProvider';
import { ScanJobsProvider } from './state/ScanJobsProvider';
import { SystemStatusProvider } from './state/SystemStatusProvider';
import './index.css';

/** Dark by default; follows prefers-color-scheme when the OS reports light. */
function usePreferredTheme(): Theme {
  const [dark, setDark] = useState<boolean>(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return true;
    }
    return !window.matchMedia('(prefers-color-scheme: light)').matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const query = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => {
      setDark(!query.matches);
    };
    query.addEventListener('change', onChange);
    return () => {
      query.removeEventListener('change', onChange);
    };
  }, []);

  return dark ? webDarkTheme : webLightTheme;
}

function Root() {
  const theme = usePreferredTheme();
  return (
    <FluentProvider theme={theme}>
      <ErrorBoundary>
        <SystemStatusProvider>
          <LiveEventsProvider>
            <ScanJobsProvider>
              <App />
            </ScanJobsProvider>
          </LiveEventsProvider>
        </SystemStatusProvider>
      </ErrorBoundary>
    </FluentProvider>
  );
}

const container = document.getElementById('root');
if (!container) {
  throw new Error('The #root container is missing from index.html');
}

createRoot(container).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
