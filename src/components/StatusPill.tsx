import type { ComponentProps } from 'react';
import { Badge } from '@fluentui/react-components';
import type { BadgeTone } from '../lib/severity';

export interface StatusPillProps {
  label: string;
  tone: BadgeTone;
  icon?: ComponentProps<typeof Badge>['icon'];
  appearance?: ComponentProps<typeof Badge>['appearance'];
  size?: ComponentProps<typeof Badge>['size'];
  title?: string;
}

/** Small labeled badge used in headers and status cards. */
export function StatusPill({ label, tone, icon, appearance = 'tint', size = 'medium', title }: StatusPillProps) {
  return (
    <Badge appearance={appearance} color={tone} icon={icon} size={size} title={title}>
      {label}
    </Badge>
  );
}
