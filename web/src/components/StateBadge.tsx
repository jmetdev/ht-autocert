import { Badge, Tooltip } from '@mantine/core';

import type { DeviceState } from '../lib/api';

const CONFIG: Record<DeviceState, { color: string; label: string; hint: string }> = {
  ok: { color: 'green', label: 'OK', hint: 'Certificate valid and not yet due for renewal' },
  renew_due: {
    color: 'yellow',
    label: 'Renew due',
    hint: 'Inside the renewal threshold for this device',
  },
  expired: { color: 'red', label: 'Expired', hint: 'Certificate has passed its expiry date' },
  missing: { color: 'gray', label: 'No certificate', hint: 'Nothing has been issued yet' },
};

export function StateBadge({ state }: { state: DeviceState }) {
  const { color, label, hint } = CONFIG[state];
  return (
    <Tooltip label={hint} withArrow>
      <Badge color={color} variant="light">
        {label}
      </Badge>
    </Tooltip>
  );
}

export function DaysBadge({
  days,
  threshold,
}: {
  days: number | null;
  threshold: number;
}) {
  if (days === null) return <Badge color="gray" variant="light">—</Badge>;

  // Colour by proximity to this device's own threshold, not a global number:
  // each gateway carries a stable offset so the fleet does not renew in a herd.
  const color = days < 0 ? 'red' : days <= threshold ? 'yellow' : 'green';
  return (
    <Tooltip label={`Renews at ${threshold} days remaining`} withArrow>
      <Badge color={color} variant="light" style={{ fontVariantNumeric: 'tabular-nums' }}>
        {days}d
      </Badge>
    </Tooltip>
  );
}
