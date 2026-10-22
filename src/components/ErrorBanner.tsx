import {
  Button,
  MessageBar,
  MessageBarActions,
  MessageBarBody,
  MessageBarTitle,
} from '@fluentui/react-components';

export interface ErrorBannerProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
}

/** Inline error surface used instead of fake data when a command fails. */
export function ErrorBanner({ title = 'Something went wrong', message, onRetry, retryLabel = 'Retry' }: ErrorBannerProps) {
  return (
    <MessageBar intent="error">
      <MessageBarBody>
        <MessageBarTitle>{title}</MessageBarTitle>
        {message}
      </MessageBarBody>
      {onRetry ? (
        <MessageBarActions>
          <Button appearance="secondary" onClick={onRetry}>
            {retryLabel}
          </Button>
        </MessageBarActions>
      ) : null}
    </MessageBar>
  );
}
