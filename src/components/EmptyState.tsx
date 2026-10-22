import type { ReactNode } from 'react';
import { Caption1, Text, makeStyles, tokens } from '@fluentui/react-components';

const useStyles = makeStyles({
  root: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    padding: '32px 16px',
    textAlign: 'center',
    color: tokens.colorNeutralForeground3,
    border: `1px dashed ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  icon: {
    fontSize: '20px',
    color: tokens.colorNeutralForeground4,
  },
  description: {
    maxWidth: '480px',
  },
});

export interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

/**
 * Explicit empty state. The dashboard never renders placeholder rows; when a
 * data source has nothing (or is unreachable) it says so here.
 */
export function EmptyState({ title, description, icon, action }: EmptyStateProps) {
  const styles = useStyles();
  return (
    <div className={styles.root}>
      {icon ? <div className={styles.icon}>{icon}</div> : null}
      <Text weight="semibold">{title}</Text>
      {description ? <Caption1 className={styles.description}>{description}</Caption1> : null}
      {action}
    </div>
  );
}
