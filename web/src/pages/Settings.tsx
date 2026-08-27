import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Loader,
  Modal,
  NumberInput,
  Paper,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import {
  IconPlus,
  IconStethoscope,
  IconTrash,
} from '@tabler/icons-react';
import { useEffect, useState } from 'react';

import {
  api,
  hasRole,
  type CAProfile,
  type DoctorReport,
  type DnsChallenges,
  type Identity,
  type Operator,
  type Role,
  type Tenant,
} from '../lib/api';

function caOptionLabel(profile: CAProfile): string {
  const kind = profile.directory_url.includes('acme-staging') ? 'staging' : 'production';
  return profile.enabled ? `${profile.name} · ${kind}` : `${profile.name} · ${kind} (disabled)`;
}

export function SettingsPage({ identity }: { identity: Identity | null }) {
  const canAdmin = hasRole(identity, 'admin');
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [profiles, setProfiles] = useState<CAProfile[]>([]);
  const [operators, setOperators] = useState<Operator[]>([]);
  const [loading, setLoading] = useState(true);

  const reload = () => {
    const jobs: Promise<unknown>[] = [api.tenants().then(setTenants), api.caProfiles().then(setProfiles)];
    if (canAdmin) jobs.push(api.operators().then(setOperators));
    Promise.all(jobs).finally(() => setLoading(false));
  };

  useEffect(reload, [canAdmin]);

  if (loading) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }

  return (
    <Stack>
      <Title order={2}>Administration</Title>
      {!canAdmin && (
        <Alert color="blue">
          This view is read-only for your role. An administrator can add, edit
          and delete tenants, CA profiles, operators and devices here.
        </Alert>
      )}

      <Tabs defaultValue="tenants">
        <Tabs.List>
          <Tabs.Tab value="tenants">Tenants</Tabs.Tab>
          <Tabs.Tab value="cas">Certificate authorities</Tabs.Tab>
          {canAdmin && <Tabs.Tab value="operators">Operators</Tabs.Tab>}
          {canAdmin && <Tabs.Tab value="diagnostics">Diagnostics</Tabs.Tab>}
        </Tabs.List>

        <Tabs.Panel value="tenants" pt="md">
          <TenantsPanel tenants={tenants} profiles={profiles} canAdmin={canAdmin} onChange={reload} />
        </Tabs.Panel>
        <Tabs.Panel value="cas" pt="md">
          <CaPanel profiles={profiles} canAdmin={canAdmin} onChange={reload} />
        </Tabs.Panel>
        {canAdmin && (
          <Tabs.Panel value="operators" pt="md">
            <OperatorsPanel operators={operators} onChange={reload} />
          </Tabs.Panel>
        )}
        {canAdmin && (
          <Tabs.Panel value="diagnostics" pt="md">
            <DiagnosticsPanel />
          </Tabs.Panel>
        )}
      </Tabs>
    </Stack>
  );
}

function TenantsPanel({
  tenants,
  profiles,
  canAdmin,
  onChange,
}: {
  tenants: Tenant[];
  profiles: CAProfile[];
  canAdmin: boolean;
  onChange: () => void;
}) {
  const [opened, { open, close }] = useDisclosure();
  const [editing, setEditing] = useState<Tenant | null>(null);
  const [credsFor, setCredsFor] = useState<Tenant | null>(null);

  return (
    <Stack>
      {canAdmin && (
        <Group justify="flex-end">
          <Button leftSection={<IconPlus size={16} />} onClick={open}>
            Add tenant
          </Button>
        </Group>
      )}
      <Paper withBorder>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Tenant</Table.Th>
              <Table.Th>Domain suffix</Table.Th>
              <Table.Th>CA profile</Table.Th>
              <Table.Th>Webex org</Table.Th>
              <Table.Th>Renew at</Table.Th>
              <Table.Th>Devices</Table.Th>
              {canAdmin && <Table.Th />}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tenants.map((tenant) => (
              <Table.Tr key={tenant.id}>
                <Table.Td>
                  <Text size="sm" fw={500}>
                    {tenant.name}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {tenant.slug}
                    {tenant.has_default_credentials ? ' · credentials set' : ' · no default credentials'}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Code>{tenant.domain_suffix}</Code>
                </Table.Td>
                <Table.Td>
                  {canAdmin ? (
                    <Select
                      size="xs"
                      w={240}
                      allowDeselect={false}
                      comboboxProps={{ withinPortal: true }}
                      data={profiles.map((p) => ({
                        value: p.name,
                        label: caOptionLabel(p),
                      }))}
                      value={tenant.ca_profile_name}
                      onChange={async (value) => {
                        if (!value || value === tenant.ca_profile_name) return;
                        try {
                          await api.updateTenant(tenant.slug, { ca: value });
                          notifications.show({
                            color: 'green',
                            message: `${tenant.slug} will issue from ${value}`,
                          });
                          onChange();
                        } catch (err) {
                          notifications.show({ color: 'red', message: (err as Error).message });
                        }
                      }}
                    />
                  ) : (
                    tenant.ca_profile_name ?? '—'
                  )}
                </Table.Td>
                <Table.Td>
                  {tenant.webex_org_name || tenant.webex_org_id ? (
                    <Text size="xs">{tenant.webex_org_name || tenant.webex_org_id}</Text>
                  ) : (
                    <Badge size="xs" color="yellow" variant="light">
                      unlinked
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>{tenant.renew_before_days}d</Table.Td>
                <Table.Td>{tenant.device_count}</Table.Td>
                {canAdmin && (
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="compact-xs" variant="light" onClick={() => setEditing(tenant)}>
                        Edit
                      </Button>
                      <Button size="compact-xs" variant="light" onClick={() => setCredsFor(tenant)}>
                        Credentials
                      </Button>
                      <Button
                        size="compact-xs"
                        color="red"
                        variant="subtle"
                        onClick={async () => {
                          if (!confirm(`Delete tenant ${tenant.slug}?`)) return;
                          try {
                            await api.deleteTenant(tenant.slug);
                            onChange();
                          } catch (err) {
                            notifications.show({ color: 'red', message: (err as Error).message });
                          }
                        }}
                      >
                        Delete
                      </Button>
                    </Group>
                  </Table.Td>
                )}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Paper>
      <TenantModal
        opened={opened || !!editing}
        tenant={editing}
        onClose={() => {
          close();
          setEditing(null);
        }}
        profiles={profiles}
        onSaved={() => {
          close();
          setEditing(null);
          onChange();
        }}
      />
      <CredentialsModal
        opened={!!credsFor}
        title={credsFor ? `Default SSH credentials for ${credsFor.slug}` : ''}
        onClose={() => setCredsFor(null)}
        onSave={async (username, password) => {
          if (!credsFor) return;
          await api.setTenantCredentials(credsFor.slug, username, password);
          notifications.show({ color: 'green', message: 'Credentials stored' });
          setCredsFor(null);
          onChange();
        }}
      />
    </Stack>
  );
}

function TenantModal({
  opened,
  onClose,
  profiles,
  onSaved,
  tenant,
}: {
  opened: boolean;
  onClose: () => void;
  profiles: CAProfile[];
  onSaved: () => void;
  tenant?: Tenant | null;
}) {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [suffix, setSuffix] = useState('');
  const [ca, setCa] = useState<string | null>(null);
  const [days, setDays] = useState<number | string>(30);
  const [busy, setBusy] = useState(false);
  const editing = Boolean(tenant);

  useEffect(() => {
    if (!opened) return;
    if (tenant) {
      setSlug(tenant.slug);
      setName(tenant.name);
      setSuffix(tenant.domain_suffix);
      setCa(tenant.ca_profile_name);
      setDays(tenant.renew_before_days);
      return;
    }
    setSlug('');
    setName('');
    setSuffix('');
    setCa(null);
    setDays(30);
  }, [opened, tenant]);

  const submit = async () => {
    if (!slug || !name || !suffix || !ca) return;
    setBusy(true);
    try {
      if (editing) {
        await api.updateTenant(slug, {
          name,
          domain_suffix: suffix,
          ca,
          renew_before_days: Number(days) || 30,
        });
        notifications.show({ color: 'green', message: `Updated tenant ${slug}` });
      } else {
        await api.createTenant({
          slug,
          name,
          domain_suffix: suffix,
          ca,
          renew_before_days: Number(days) || 30,
        });
        notifications.show({ color: 'green', message: `Added tenant ${slug}` });
      }
      onSaved();
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title={editing ? `Edit ${tenant?.slug}` : 'Add tenant'}>
      <Stack>
        <TextInput
          label="Slug"
          placeholder="husd"
          value={slug}
          disabled={editing}
          onChange={(e) => setSlug(e.currentTarget.value)}
        />
        <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} />
        <TextInput
          label="Domain suffix"
          placeholder="husd.clients.managedcollab.com"
          value={suffix}
          onChange={(e) => setSuffix(e.currentTarget.value)}
        />
        <Select
          label="CA profile"
          description="The next issuance for this tenant uses this CA. Existing certificates stay as they are until you re-issue."
          allowDeselect={false}
          comboboxProps={{ withinPortal: true }}
          data={profiles.map((p) => ({
            value: p.name,
            label: caOptionLabel(p),
          }))}
          value={ca}
          onChange={setCa}
        />
        <NumberInput label="Renew before (days)" value={days} onChange={setDays} min={1} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={busy} disabled={!slug || !name || !suffix || !ca}>
            {editing ? 'Save' : 'Add'}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function CaPanel({
  profiles,
  canAdmin,
  onChange,
}: {
  profiles: CAProfile[];
  canAdmin: boolean;
  onChange: () => void;
}) {
  const [opened, { open, close }] = useDisclosure();

  return (
    <Stack>
      {canAdmin && (
        <Group justify="flex-end">
          <Button leftSection={<IconPlus size={16} />} onClick={open}>
            Add CA profile
          </Button>
        </Group>
      )}
      <Paper withBorder>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Directory</Table.Th>
              <Table.Th>Preferred chain</Table.Th>
              <Table.Th>Account</Table.Th>
              {canAdmin && <Table.Th />}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {profiles.map((profile) => (
              <Table.Tr key={profile.id}>
                <Table.Td>
                  <Group gap="xs">
                    <Text size="sm">{profile.name}</Text>
                    {profile.uses_eab && (
                      <Badge size="xs" variant="light" color="grape">
                        EAB
                      </Badge>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {profile.directory_url}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{profile.preferred_chain ?? 'CA default'}</Text>
                </Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light" color={profile.registered ? 'green' : 'gray'}>
                    {profile.registered ? 'registered' : 'not registered'}
                  </Badge>
                </Table.Td>
                {canAdmin && (
                  <Table.Td>
                    <Button
                      size="compact-xs"
                      color="red"
                      variant="subtle"
                      onClick={async () => {
                        if (!confirm(`Delete CA profile ${profile.name}?`)) return;
                        try {
                          await api.deleteCaProfile(profile.name);
                          onChange();
                        } catch (err) {
                          notifications.show({ color: 'red', message: (err as Error).message });
                        }
                      }}
                    >
                      Delete
                    </Button>
                  </Table.Td>
                )}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Paper>
      <CaModal
        opened={opened}
        onClose={close}
        onSaved={() => {
          close();
          onChange();
        }}
      />
    </Stack>
  );
}

function CaModal({
  opened,
  onClose,
  onSaved,
}: {
  opened: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [staging, setStaging] = useState(true);
  const [directory, setDirectory] = useState('');
  const [chain, setChain] = useState('');
  const [eabKid, setEabKid] = useState('');
  const [eabHmac, setEabHmac] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!name || !email) return;
    setBusy(true);
    try {
      await api.createCaProfile({
        name,
        email,
        staging,
        directory_url: directory || undefined,
        preferred_chain: chain || undefined,
        eab_kid: eabKid || undefined,
        eab_hmac: eabHmac || undefined,
      });
      notifications.show({ color: 'green', message: `Added CA ${name}` });
      onSaved();
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title="Add CA profile">
      <Stack>
        <TextInput label="Name" placeholder="letsencrypt-staging" value={name} onChange={(e) => setName(e.currentTarget.value)} />
        <TextInput label="Contact email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
        <Switch
          checked={staging}
          onChange={(e) => setStaging(e.currentTarget.checked)}
          label="Let's Encrypt staging"
        />
        <TextInput
          label="Directory URL (optional)"
          description="Leave blank for Let's Encrypt production, or when staging is on."
          value={directory}
          onChange={(e) => setDirectory(e.currentTarget.value)}
        />
        <TextInput
          label="Preferred chain"
          placeholder="ISRG Root X1"
          value={chain}
          onChange={(e) => setChain(e.currentTarget.value)}
        />
        <TextInput label="EAB key id" value={eabKid} onChange={(e) => setEabKid(e.currentTarget.value)} />
        <PasswordInput label="EAB HMAC" value={eabHmac} onChange={(e) => setEabHmac(e.currentTarget.value)} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={busy} disabled={!name || !email}>
            Add
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function OperatorsPanel({ operators, onChange }: { operators: Operator[]; onChange: () => void }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [busy, setBusy] = useState(false);

  const add = async () => {
    if (!email) return;
    setBusy(true);
    try {
      await api.createOperator(email, role);
      notifications.show({ color: 'green', message: `Granted ${role} to ${email}` });
      setEmail('');
      onChange();
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group align="flex-end">
        <TextInput
          label="Webex email"
          placeholder="engineer@example.com"
          value={email}
          onChange={(e) => setEmail(e.currentTarget.value)}
          w={280}
        />
        <Select
          label="Role"
          data={[
            { value: 'viewer', label: 'viewer' },
            { value: 'operator', label: 'operator' },
            { value: 'admin', label: 'admin' },
          ]}
          value={role}
          onChange={(v) => setRole((v as Role) || 'viewer')}
          w={140}
        />
        <Button onClick={add} loading={busy} disabled={!email}>
          Grant access
        </Button>
      </Group>
      <Paper withBorder>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Email</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>Last seen</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {operators.map((op) => (
              <Table.Tr key={op.email}>
                <Table.Td>
                  <Text size="sm">{op.email}</Text>
                  {op.source === 'bootstrap' && (
                    <Badge size="xs" color="yellow" variant="light">
                      bootstrap
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  {op.source === 'bootstrap' ? (
                    <Text size="sm">{op.role}</Text>
                  ) : (
                    <Select
                      size="xs"
                      data={['viewer', 'operator', 'admin']}
                      value={op.role}
                      onChange={async (v) => {
                        if (!v) return;
                        try {
                          await api.updateOperator(op.email, { role: v as Role });
                          onChange();
                        } catch (err) {
                          notifications.show({ color: 'red', message: (err as Error).message });
                        }
                      }}
                      w={130}
                    />
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {op.last_seen_at ? new Date(op.last_seen_at).toLocaleString() : 'never'}
                    {!op.enabled ? ' · disabled' : ''}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {op.source !== 'bootstrap' && (
                    <Button
                      size="compact-xs"
                      color="red"
                      variant="subtle"
                      leftSection={<IconTrash size={12} />}
                      onClick={async () => {
                        try {
                          await api.deleteOperator(op.email);
                          onChange();
                        } catch (err) {
                          notifications.show({ color: 'red', message: (err as Error).message });
                        }
                      }}
                    >
                      Remove
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Paper>
    </Stack>
  );
}

function DiagnosticsPanel() {
  const [report, setReport] = useState<DoctorReport | null>(null);
  const [dns, setDns] = useState<DnsChallenges | null>(null);
  const [busy, setBusy] = useState(false);

  const runDoctor = async () => {
    setBusy(true);
    try {
      setReport(await api.doctor());
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const loadDns = async () => {
    setBusy(true);
    try {
      setDns(await api.dnsChallenges());
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group>
        <Button leftSection={<IconStethoscope size={16} />} onClick={runDoctor} loading={busy}>
          Run doctor
        </Button>
        <Button variant="default" onClick={loadDns} loading={busy}>
          List DNS challenges
        </Button>
        {dns && dns.records.length > 0 && (
          <Button
            color="red"
            variant="light"
            onClick={async () => {
              if (!confirm(`Delete ${dns.records.length} leftover challenge record(s)?`)) return;
              setBusy(true);
              try {
                const result = await api.deleteDnsChallenges();
                setDns(result);
                notifications.show({ color: 'green', message: `Deleted ${result.deleted} record(s)` });
              } catch (err) {
                notifications.show({ color: 'red', message: (err as Error).message });
              } finally {
                setBusy(false);
              }
            }}
          >
            Delete leftover challenges
          </Button>
        )}
      </Group>

      {report && (
        <Paper withBorder p="md">
          <Text fw={600} mb="sm">
            {report.failures} failure(s), {report.warnings} warning(s)
          </Text>
          <Stack gap={6}>
            {report.checks.map((check, i) => (
              <Group key={`${check.name}-${i}`} gap="sm" wrap="nowrap" align="flex-start">
                <Badge
                  size="sm"
                  color={check.status === 'ok' ? 'green' : check.status === 'warn' ? 'yellow' : 'red'}
                >
                  {check.status}
                </Badge>
                <div>
                  <Text size="sm">{check.name}</Text>
                  <Text size="xs" c="dimmed">
                    {check.detail}
                    {check.remedy ? ` — ${check.remedy}` : ''}
                  </Text>
                </div>
              </Group>
            ))}
          </Stack>
        </Paper>
      )}

      {dns && (
        <Paper withBorder p="md">
          <Text fw={600} mb="xs">
            {dns.records.length} challenge record(s) in {dns.zone}
          </Text>
          {dns.records.length === 0 ? (
            <Text size="sm" c="dimmed">
              None.
            </Text>
          ) : (
            dns.records.map((r) => (
              <Text key={r.record_id} size="sm" ff="monospace">
                {r.name}
              </Text>
            ))
          )}
        </Paper>
      )}
    </Stack>
  );
}

function CredentialsModal({
  opened,
  title,
  onClose,
  onSave,
}: {
  opened: boolean;
  title: string;
  onClose: () => void;
  onSave: (username: string, password: string, enable?: string) => Promise<void>;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [enable, setEnable] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      await onSave(username, password, enable || undefined);
      setUsername('');
      setPassword('');
      setEnable('');
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title={title}>
      <Stack>
        <TextInput label="Username" value={username} onChange={(e) => setUsername(e.currentTarget.value)} />
        <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
        <PasswordInput
          label="Enable password (optional)"
          value={enable}
          onChange={(e) => setEnable(e.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={busy} disabled={!username || !password}>
            Store
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
