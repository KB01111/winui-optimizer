import { Badge } from '@fluentui/react-components';
import type { Severity } from '../api/types';
import { humanize, severityTone } from '../lib/severity';
import { formatNumber } from '../lib/format';

export interface SeverityBadgeProps {
  severity: Severity;
  count?: number;
  size?: 'small' | 'medium' | 'large';
}

/** Severity badge with consistent tone mapping across the dashboard. */
export function SeverityBadge({ severity, count, size = 'small' }: SeverityBadgeProps) {
  const label = count === undefined ? humanize(severity) : `${humanize(severity)} · ${formatNumber(count)}`;
  return (
    <Badge appearance="tint" color={severityTone(severity)} size={size}>
      {label}
    </Badge>
  );
}
