import {
  Alert,
  Anchor,
  Badge,
  Card,
  Group,
  Loader,
  Paper,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import { IconAlertTriangle, IconClock, IconSearch } from '@tabler/icons-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { DaysBadge, StateBadge } from '../components/StateBadge';
import { api, type Device, type Summary } from '../lib/api';

function StatCard({
  label,
  value,
  color,
  hint,
}: {
  label: string;
  value: number | string;
  color?: string;
  hint?: string;
}) {
  const card = (
    <Card withBorder padding="md">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text size="xl" fw={700} c={color}>
        {value}
      </Text>
    </Card>
  );
  return hint ? (
    <Tooltip label={hint} withArrow>
      {card}
    </Tooltip>
  ) : (
    card
  );
}

export function FleetPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.devices(), api.summary()])
      .then(([d, s]) => {
        if (cancelled) return;
        setDevices(d);
        setSummary(s);
        setError(null);
      })
      .catch((err) => !cancelled && setError(err.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  const visible = useMemo(() => {
    const term = search.trim().toLowerCase();
    return devices.filter((device) => {
      if (filter !== 'all' && device.state !== filter) return false;
      if (!term) return true;
      return (
        device.fqdn.toLowerCase().includes(term) ||
        device.tenant_slug.toLowerCase().includes(term) ||
        device.mgmt_address.includes(term)
      );
    });
  }, [devices, filter, search]);

  if (loading) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }

  return (
    <Stack>
      <Title order={2}>Fleet</Title>

      {error && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />}>
          {error}
        </Alert>
      )}

      {summary && (
        <>
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }}>
            <StatCard label="Devices" value={summary.devices} />
            <StatCard label="OK" value={summary.ok} color="green" />
            <StatCard label="Renew due" value={summary.renew_due} color="yellow" />
            <StatCard label="Expired" value={summary.expired} color="red" />
            <StatCard label="No cert" value={summary.missing} color="gray" />
            <StatCard
              label="≤14 days"
              value={summary.expiring_within_14d}
              color={summary.expiring_within_14d > 0 ? 'orange' : undefined}
              hint="Certificates expiring within two weeks"
            />
          </SimpleGrid>

          <Paper withBorder p="xs">
            <Group gap="xs">
              <IconClock size={16} />
              <Text size="sm">
                Scheduler{' '}
                <Badge
                  size="sm"
                  variant="light"
                  color={summary.scheduler_enabled ? 'green' : 'gray'}
                >
                  {summary.scheduler_enabled ? 'enabled' : 'disabled'}
                </Badge>
              </Text>
              {summary.next_run_at && (
                <Text size="sm" c="dimmed">
                  Next run {new Date(summary.next_run_at).toLocaleString()}
                </Text>
              )}
              {summary.last_run_at && (
                <Text size="sm" c="dimmed">
                  · Last run {new Date(summary.last_run_at).toLocaleString()} (
                  {summary.last_run_status})
                </Text>
              )}
            </Group>
          </Paper>
        </>
      )}

      <Group justify="space-between">
        <SegmentedControl
          value={filter}
          onChange={setFilter}
          data={[
            { label: 'All', value: 'all' },
            { label: 'OK', value: 'ok' },
            { label: 'Renew due', value: 'renew_due' },
            { label: 'Expired', value: 'expired' },
            { label: 'No cert', value: 'missing' },
          ]}
        />
        <TextInput
          placeholder="Filter by FQDN, tenant or address"
          leftSection={<IconSearch size={16} />}
          value={search}
          onChange={(event) => setSearch(event.currentTarget.value)}
          w={320}
        />
      </Group>

      <Paper withBorder>
        <Table.ScrollContainer minWidth={900}>
          <Table highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Gateway</Table.Th>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th>Remaining</Table.Th>
                <Table.Th>Active trustpoint</Table.Th>
                <Table.Th>Chain</Table.Th>
                <Table.Th>p12</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {visible.map((device) => (
                <Table.Tr key={device.fqdn}>
                  <Table.Td>
                    <Anchor component={Link} to={`/devices/${device.fqdn}`} size="sm">
                      {device.fqdn}
                    </Anchor>
                    <Text size="xs" c="dimmed">
                      {device.mgmt_address}
                      {!device.has_credentials && ' · no credentials set'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{device.tenant_slug}</Text>
                  </Table.Td>
                  <Table.Td>
                    <StateBadge state={device.state} />
                  </Table.Td>
                  <Table.Td>
                    <DaysBadge
                      days={device.days_remaining}
                      threshold={device.renewal_threshold}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {device.active_trustpoint ?? '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed">
                      {device.chain_issuer_cn ?? '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge
                      size="sm"
                      variant="light"
                      color={device.pkcs12_profile === 'legacy' ? 'orange' : 'blue'}
                    >
                      {device.pkcs12_profile}
                    </Badge>
                  </Table.Td>
                </Table.Tr>
              ))}
              {visible.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={7}>
                    <Text size="sm" c="dimmed" ta="center" py="md">
                      No gateways match this filter.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>
    </Stack>
  );
}
