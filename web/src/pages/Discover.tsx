import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Paper,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  Title,
  Tooltip,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import {
  IconAlertTriangle,
  IconDownload,
  IconInfoCircle,
  IconLink,
} from '@tabler/icons-react';
import { useEffect, useMemo, useState } from 'react';

import {
  api,
  hasRole,
  type Identity,
  type Tenant,
  type WebexImport,
} from '../lib/api';
import { useWebexOrg } from '../lib/webexOrg';

export function DiscoverPage({ identity }: { identity: Identity | null }) {
  const canOperate = hasRole(identity, 'operator');
  const canAdmin = hasRole(identity, 'admin');
  const { org, orgId, reload: reloadOrgs } = useWebexOrg();

  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenant, setTenant] = useState<string | null>(null);
  const [apply, setApply] = useState(false);
  const [result, setResult] = useState<WebexImport | null>(null);
  const [busy, setBusy] = useState(false);

  const loadTenants = () => api.tenants().then(setTenants);
  useEffect(() => {
    loadTenants();
  }, []);

  // Follow the toolbar: selecting an org selects the tenant it is linked to.
  useEffect(() => {
    setResult(null);
    if (!orgId) return;
    const linked = tenants.find((t) => t.webex_org_id === orgId);
    if (linked) setTenant(linked.slug);
  }, [orgId, tenants]);

  const selectedTenant = tenants.find((t) => t.slug === tenant) ?? null;
  const mismatch =
    selectedTenant?.webex_org_id && orgId && selectedTenant.webex_org_id !== orgId;

  const derivedCount = useMemo(
    () =>
      result?.candidates.filter((c) => c.importable && c.fqdn_source === 'derived')
        .length ?? 0,
    [result],
  );

  const run = async (doApply: boolean) => {
    if (!tenant || !orgId) return;
    setBusy(true);
    try {
      const outcome = await api.webexImport(tenant, orgId, doApply);
      setResult(outcome);
      if (doApply) {
        notifications.show({
          color: 'green',
          title: 'Import complete',
          message: `Created ${outcome.imported} device(s), disabled pending review.`,
        });
      }
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const link = async () => {
    if (!tenant || !org) return;
    try {
      await api.linkWebexOrg(tenant, org.org_id, org.display_name);
      await loadTenants();
      reloadOrgs();
      notifications.show({
        color: 'green',
        message: `${org.display_name} linked to ${tenant}.`,
      });
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    }
  };

  return (
    <Stack>
      <Title order={2}>Discover gateways</Title>
      <Text size="sm" c="dimmed">
        Reads Webex Control Hub with your own signed-in token, so it sees exactly
        what your Control Hub rights allow. A Local Gateway appears in Webex as a{' '}
        <b>trunk</b>, so that is what is listed here.
      </Text>

      {!canOperate && (
        <Alert color="yellow" icon={<IconAlertTriangle size={16} />}>
          Discovery requires the operator role.
        </Alert>
      )}

      {!orgId && (
        <Alert color="blue" icon={<IconInfoCircle size={16} />}>
          Pick a Webex organisation in the toolbar. Each client is a separate
          organisation in Control Hub.
        </Alert>
      )}

      <Group align="flex-end">
        <Select
          label="Import into tenant"
          placeholder="Pick a tenant"
          data={tenants.map((t) => ({
            value: t.slug,
            label: `${t.name} (${t.slug})`,
          }))}
          value={tenant}
          onChange={setTenant}
          w={300}
          searchable
        />
        <Button
          variant="default"
          onClick={() => run(false)}
          loading={busy && !apply}
          disabled={!tenant || !orgId || !canOperate}
        >
          Preview
        </Button>
        <Switch
          checked={apply}
          onChange={(e) => setApply(e.currentTarget.checked)}
          label="Create devices"
          description={apply ? 'Will create records' : 'Preview only'}
        />
        <Button
          leftSection={<IconDownload size={16} />}
          onClick={() => run(true)}
          loading={busy && apply}
          disabled={!tenant || !orgId || !canOperate || !apply}
        >
          Import
        </Button>
        {canAdmin && org && tenant && !mismatch && selectedTenant?.webex_org_id !== orgId && (
          <Button
            variant="light"
            leftSection={<IconLink size={16} />}
            onClick={link}
          >
            Link org to {tenant}
          </Button>
        )}
      </Group>

      {mismatch && (
        <Alert color="orange" icon={<IconAlertTriangle size={16} />} title="Organisation mismatch">
          Tenant <Code>{tenant}</Code> is linked to a different Webex
          organisation than the one selected in the toolbar. Importing would
          attach another customer&rsquo;s gateways to this tenant. Switch the
          toolbar back, or pick the matching tenant.
        </Alert>
      )}

      {result && (
        <>
          <Group justify="space-between" mt="md">
            <Title order={4}>
              {result.found} trunk(s) in {org?.display_name ?? result.org_id}
            </Title>
            {!result.applied && (
              <Text size="xs" c="dimmed">
                Preview — enable “Create devices” to apply
              </Text>
            )}
          </Group>

          {derivedCount > 0 && (
            <Alert color="yellow" icon={<IconAlertTriangle size={16} />}>
              {derivedCount} certificate name(s) were <b>derived from the tenant
              domain suffix</b>, not read from Webex. Registering trunks do not
              record an address in Control Hub, so Webex cannot tell us the name
              the certificate must carry. Confirm each one before enabling the
              device.
            </Alert>
          )}

          <Paper withBorder>
            <Table verticalSpacing="xs" horizontalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Trunk</Table.Th>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Certificate name</Table.Th>
                  <Table.Th>Status</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {result.candidates.map((c) => (
                  <Table.Tr key={c.trunk_id}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {c.name}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {[c.device_type, c.location].filter(Boolean).join(' · ') || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        size="xs"
                        variant="light"
                        color={c.trunk_type === 'CERTIFICATE_BASED' ? 'blue' : 'gray'}
                      >
                        {c.trunk_type === 'CERTIFICATE_BASED' ? 'cert-based' : 'registering'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" ff="monospace">
                        {c.proposed_fqdn ?? '—'}
                      </Text>
                      {c.fqdn_source === 'derived' && (
                        <Tooltip label="Webex has no address for a registering trunk; this was built from the tenant domain suffix.">
                          <Text size="xs" c="yellow.7">
                            derived — confirm
                          </Text>
                        </Tooltip>
                      )}
                      {c.fqdn_source === 'webex' && (
                        <Text size="xs" c="dimmed">
                          from Webex
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {c.importable ? (
                        <Badge size="sm" color="green" variant="light">
                          {result.applied ? 'created' : 'will import'}
                        </Badge>
                      ) : (
                        <Text size="xs" c="dimmed">
                          {c.reason}
                        </Text>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Paper>
        </>
      )}

      {result?.applied && result.imported > 0 && (
        <Alert color="blue" icon={<IconInfoCircle size={16} />} title="Imported devices are disabled">
          Control Hub knows a trunk&rsquo;s name but never its management
          address, SSH host key or credentials, so these are worklist entries
          rather than deployable devices. The renewal scheduler skips disabled
          devices, so nothing will act on them until you finish and enable each
          one:
          <Code block mt="xs">
            ./htac device trust &lt;fqdn&gt;{'\n'}
            ./htac device set-credentials &lt;fqdn&gt;
          </Code>
        </Alert>
      )}
    </Stack>
  );
}
