import { Component, type ErrorInfo, type ReactNode } from 'react';
import {
  Body1,
  Button,
  MessageBar,
  MessageBarActions,
  MessageBarBody,
  MessageBarTitle,
  makeStyles,
  tokens,
} from '@fluentui/react-components';

const useStyles = makeStyles({
  root: {
    padding: '24px',
    minHeight: '100vh',
    boxSizing: 'border-box',
    backgroundColor: tokens.colorNeutralBackground1,
  },
});

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/** Last-resort boundary so a render error never leaves a blank webview. */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('AI Antivirus dashboard crashed while rendering:', error, info.componentStack);
  }

  private readonly reset = (): void => {
    this.setState({ error: null });
  };

  override render(): ReactNode {
    if (this.state.error) {
      return <ErrorFallback error={this.state.error} onReset={this.reset} />;
    }
    return this.props.children;
  }
}

function ErrorFallback({ error, onReset }: { error: Error; onReset: () => void }) {
  const styles = useStyles();
  return (
    <div className={styles.root}>
      <MessageBar intent="error">
        <MessageBarBody>
          <MessageBarTitle>The dashboard hit an unexpected error</MessageBarTitle>
          <Body1>{error.message}</Body1>
        </MessageBarBody>
        <MessageBarActions>
          <Button appearance="secondary" onClick={onReset}>
            Try again
          </Button>
        </MessageBarActions>
      </MessageBar>
    </div>
  );
}
