import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Loader,
  Modal,
  NumberInput,
  Paper,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import {
  IconAlertTriangle,
  IconClock,
  IconPlus,
  IconSearch,
} from '@tabler/icons-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { DaysBadge, StateBadge } from '../components/StateBadge';
import {
  api,
  hasRole,
  type Device,
  type Identity,
  type Summary,
  type Tenant,
} from '../lib/api';
import { useWebexOrg } from '../lib/webexOrg';

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

export function FleetPage({ identity }: { identity: Identity | null }) {
  const canAdmin = hasRole(identity, 'admin');
  const { org, orgId } = useWebexOrg();
  const tenantSlug = org?.tenant_slug ?? null;

  const [devices, setDevices] = useState<Device[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure();

  const load = () => {
    setLoading(true);
    if (orgId && !tenantSlug) {
      setDevices([]);
      setSummary(null);
      setError(null);
      api.tenants().then(setTenants).finally(() => setLoading(false));
      return;
    }
    const scope = tenantSlug ? { tenant: tenantSlug } : undefined;
    Promise.all([api.devices(scope), api.summary(scope), api.tenants()])
      .then(([d, s, t]) => {
        setDevices(d);
        setSummary(s);
        setTenants(t);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, tenantSlug]);

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
      <Group justify="space-between">
        <div>
          <Title order={2}>Fleet</Title>
          {org && (
            <Text size="sm" c="dimmed">
              {org.display_name}
              {tenantSlug ? ` · tenant ${tenantSlug}` : ''}
            </Text>
          )}
        </div>
        {canAdmin && (
          <Button leftSection={<IconPlus size={16} />} onClick={openAdd}>
            Add gateway
          </Button>
        )}
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />}>
          {error}
        </Alert>
      )}

      {orgId && !tenantSlug && (
        <Alert color="yellow" icon={<IconAlertTriangle size={16} />}>
          {org?.display_name ?? 'This organisation'} is not linked to a tenant yet,
          so there is no inventory to show. Link it under Administration.
        </Alert>
      )}

      {!orgId && (
        <Alert color="blue">
          No organisation selected — showing every tenant. Pick one in the
          toolbar to see a single customer.
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
                    <AnchorFqdn fqdn={device.fqdn} />
                    <Text size="xs" c="dimmed">
                      {device.mgmt_address}
                      {!device.enabled && ' · disabled'}
                      {!device.has_credentials && ' · no credentials'}
                      {!device.has_host_key && ' · host key not pinned'}
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

      <AddDeviceModal
        opened={addOpened}
        onClose={closeAdd}
        tenants={tenants}
        defaultTenant={tenantSlug}
        onCreated={() => {
          closeAdd();
          load();
        }}
      />
    </Stack>
  );
}

function AnchorFqdn({ fqdn }: { fqdn: string }) {
  return (
    <Text
      component={Link}
      to={`/devices/${encodeURIComponent(fqdn)}`}
      size="sm"
      c="blue"
      td="underline"
    >
      {fqdn}
    </Text>
  );
}

function AddDeviceModal({
  opened,
  onClose,
  tenants,
  defaultTenant,
  onCreated,
}: {
  opened: boolean;
  onClose: () => void;
  tenants: Tenant[];
  defaultTenant: string | null;
  onCreated: () => void;
}) {
  const [tenant, setTenant] = useState<string | null>(defaultTenant);
  const [hostname, setHostname] = useState('');
  const [fqdn, setFqdn] = useState('');
  const [address, setAddress] = useState('');
  const [sshPort, setSshPort] = useState<number | string>(22);
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (opened) setTenant(defaultTenant);
  }, [opened, defaultTenant]);

  const submit = async () => {
    if (!tenant || !hostname || !fqdn || !address) return;
    setBusy(true);
    try {
      await api.createDevice({
        tenant,
        hostname,
        fqdn,
        address,
        ssh_port: Number(sshPort) || 22,
        pkcs12_profile: 'modern',
        extra_sans: [],
        enabled,
      });
      notifications.show({ color: 'green', message: `Added ${fqdn}` });
      onCreated();
      setHostname('');
      setFqdn('');
      setAddress('');
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title="Add gateway">
      <Stack>
        <Select
          label="Tenant"
          data={tenants.map((t) => ({ value: t.slug, label: `${t.name} (${t.slug})` }))}
          value={tenant}
          onChange={setTenant}
          searchable
        />
        <TextInput
          label="Hostname"
          placeholder="brg-vgw-01"
          value={hostname}
          onChange={(e) => setHostname(e.currentTarget.value)}
        />
        <TextInput
          label="Certificate FQDN"
          placeholder="brg-vgw-01.client.example.com"
          value={fqdn}
          onChange={(e) => setFqdn(e.currentTarget.value)}
        />
        <TextInput
          label="Management address"
          placeholder="10.0.0.1"
          value={address}
          onChange={(e) => setAddress(e.currentTarget.value)}
        />
        <NumberInput label="SSH port" value={sshPort} onChange={setSshPort} min={1} />
        <Switch
          checked={enabled}
          onChange={(e) => setEnabled(e.currentTarget.checked)}
          label="Enable now"
          description="Leave off until credentials and the SSH host key are set."
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={busy} disabled={!tenant || !hostname || !fqdn || !address}>
            Add
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
