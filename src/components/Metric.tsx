import type { ReactNode } from 'react';
import { Caption1, Text, makeStyles, mergeClasses, tokens } from '@fluentui/react-components';

const useStyles = makeStyles({
  root: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    minWidth: 0,
  },
  value: {
    lineHeight: tokens.lineHeightBase600,
  },
  hint: {
    color: tokens.colorNeutralForeground3,
  },
  good: { color: tokens.colorStatusSuccessForeground1 },
  warn: { color: tokens.colorStatusWarningForeground1 },
  bad: { color: tokens.colorStatusDangerForeground1 },
  neutral: { color: tokens.colorNeutralForeground1 },
});

export interface MetricProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
}

/** Headline number with an explicit hint line (never a bare unknown value). */
export function Metric({ label, value, hint, tone = 'neutral' }: MetricProps) {
  const styles = useStyles();
  const toneClass =
    tone === 'good'
      ? styles.good
      : tone === 'warn'
        ? styles.warn
        : tone === 'bad'
          ? styles.bad
          : styles.neutral;
  return (
    <div className={styles.root}>
      <Caption1 className={styles.hint}>{label}</Caption1>
      <Text size={600} weight="semibold" className={mergeClasses(styles.value, toneClass)}>
        {value}
      </Text>
      {hint !== undefined ? <Caption1 className={styles.hint}>{hint}</Caption1> : null}
    </div>
  );
}
