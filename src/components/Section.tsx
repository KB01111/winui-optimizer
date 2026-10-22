import type { ReactNode } from 'react';
import { Caption1, Card, Subtitle2, Text, makeStyles, tokens } from '@fluentui/react-components';

const useStyles = makeStyles({
  card: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    padding: '16px',
    minWidth: 0,
  },
  header: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '8px',
    flexWrap: 'wrap',
  },
  titleBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    minWidth: 0,
  },
  subtitle: {
    color: tokens.colorNeutralForeground3,
  },
  body: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    minWidth: 0,
  },
});

export interface SectionProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  /** Render without the Card outline (for use inside drawers/dialogs). */
  plain?: boolean;
}

/** Card section with a consistent header row. */
export function Section({ title, subtitle, action, children, plain = false }: SectionProps) {
  const styles = useStyles();
  const body = (
    <div className={styles.body}>
      <div className={styles.header}>
        <div className={styles.titleBlock}>
          {plain ? (
            <Subtitle2>{title}</Subtitle2>
          ) : (
            <Text weight="semibold" size={400}>
              {title}
            </Text>
          )}
          {subtitle ? <Caption1 className={styles.subtitle}>{subtitle}</Caption1> : null}
        </div>
        {action}
      </div>
      {children}
    </div>
  );

  if (plain) {
    return body;
  }
  return <Card appearance="outline" className={styles.card}>{body}</Card>;
}
