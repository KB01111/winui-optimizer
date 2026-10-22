import type { ReactNode } from 'react';
import { makeStyles, tokens } from '@fluentui/react-components';

const useStyles = makeStyles({
  row: {
    display: 'grid',
    gridTemplateColumns: 'minmax(120px, 34%) 1fr',
    gap: '8px',
    padding: '3px 0',
    alignItems: 'baseline',
  },
  label: {
    color: tokens.colorNeutralForeground3,
    fontSize: tokens.fontSizeBase200,
    lineHeight: tokens.lineHeightBase300,
  },
  value: {
    color: tokens.colorNeutralForeground1,
    fontSize: tokens.fontSizeBase300,
    overflowWrap: 'anywhere',
  },
  mono: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    overflowWrap: 'anywhere',
  },
});

export interface KeyValueProps {
  label: string;
  value?: ReactNode;
  mono?: boolean;
}

/** Dense label/value row used by every status card. */
export function KeyValue({ label, value, mono = false }: KeyValueProps) {
  const styles = useStyles();
  const content = value === undefined || value === null || value === '' ? '—' : value;
  return (
    <div className={styles.row}>
      <span className={styles.label}>{label}</span>
      <span className={mono ? styles.mono : styles.value}>{content}</span>
    </div>
  );
}
