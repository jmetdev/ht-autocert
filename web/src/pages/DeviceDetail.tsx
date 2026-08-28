import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Code,
  Divider,
  Group,
  List,
  Loader,
  Modal,
  NumberInput,
  Paper,
  PasswordInput,
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
  IconArrowLeft,
  IconCertificate,
  IconDownload,
  IconKey,
  IconRefresh,
  IconTrash,
  IconUpload,
} from '@tabler/icons-react';
import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { DaysBadge, StateBadge } from '../components/StateBadge';
import {
  api,
  hasRole,
  type DeviceDetail,
  type Identity,
  type LiveState,
} from '../lib/api';

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text size="sm">{value}</Text>
    </div>
  );
}

export function DeviceDetailPage({ identity }: { identity: Identity | null }) {
  const canOperate = hasRole(identity, 'operator');
  const canAdmin = hasRole(identity, 'admin');
  const { fqdn = '' } = useParams();
  const navigate = useNavigate();
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [live, setLive] = useState<LiveState | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [rebind, setRebind] = useState(true);
  const [mgmtAddress, setMgmtAddress] = useState('');
  const [confirmOpened, { open: openConfirm, close: closeConfirm }] = useDisclosure();
  const [credsOpened, { open: openCreds, close: closeCreds }] = useDisclosure();
  const [steps, setSteps] = useState<string[]>([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [enablePassword, setEnablePassword] = useState('');
  const [address, setAddress] = useState('');
  const [sshPort, setSshPort] = useState<number | string>(22);
  const [sans, setSans] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [p12Profile, setP12Profile] = useState('modern');

  const load = useCallback(() => {
    setLoading(true);
    api
      .device(fqdn)
      .then((d) => {
        setDevice(d);
        setMgmtAddress(d.mgmt_address);
        setAddress(d.mgmt_address);
        setSshPort(d.ssh_port);
        setSans((d.extra_sans ?? []).join(', '));
        setEnabled(d.enabled);
        setP12Profile(d.pkcs12_profile);
      })
      .catch((err) => notifications.show({ color: 'red', message: err.message }))
      .finally(() => setLoading(false));
  }, [fqdn]);

  useEffect(load, [load]);

  const readLive = () => {
    setLiveError(null);
    setLive(null);
    api
      .liveState(fqdn)
      .then(setLive)
      .catch((err) => setLiveError(err.message));
  };

  const issue = async () => {
    setBusy(true);
    try {
      const result = await api.issue(fqdn, true);
      notifications.show({
        color: result.status === 'issued' ? 'green' : 'red',
        title: `Issue: ${result.status}`,
        message: result.detail,
      });
      load();
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const saveMgmt = async () => {
    setBusy(true);
    try {
      const updated = await api.setAddress(fqdn, mgmtAddress);
      setDevice(updated);
      setMgmtAddress(updated.mgmt_address);
      setAddress(updated.mgmt_address);
      notifications.show({
        color: 'green',
        message: `Management address set to ${updated.mgmt_address}`,
      });
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const deploy = async () => {
    closeConfirm();
    setBusy(true);
    setSteps([]);
    try {
      const result = await api.deploy(fqdn, rebind);
      setSteps(result.steps);
      notifications.show({
        color:
          result.status === 'deployed'
            ? 'green'
            : result.status === 'rolled_back'
              ? 'yellow'
              : 'red',
        title: `Deploy: ${result.status}`,
        message: result.detail,
        autoClose: result.status === 'deployed' ? 5000 : false,
      });
      load();
    } catch (err) {
      notifications.show({ color: 'red', message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  if (loading || !device) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }

  return (
    <Stack>
      <Group>
        <Anchor component={Link} to="/fleet" size="sm">
          <Group gap={4}>
            <IconArrowLeft size={14} /> Fleet
          </Group>
        </Anchor>
      </Group>

      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{device.fqdn}</Title>
          <Text c="dimmed" size="sm">
            {device.tenant_name}
            {device.has_mgmt_address ? ` · ${device.mgmt_address}` : ' · no management IP'}
          </Text>
        </div>
        <Group>
          <StateBadge state={device.state} />
          <DaysBadge days={device.days_remaining} threshold={device.renewal_threshold} />
        </Group>
      </Group>

      {!device.has_mgmt_address && (
        <Alert color="orange" icon={<IconAlertTriangle size={16} />}>
          No management IP. The certificate FQDN is for ACME DNS-01 only and has
          no A record, so live state, SSH and RESTCONF cannot use it. Set the
          IOS management address below (reachable via Twingate).
        </Alert>
      )}

      {!device.has_credentials && (
        <Alert color="yellow" icon={<IconAlertTriangle size={16} />}>
          No SSH credentials are set for this gateway or its tenant, so deployment
          will fail.{canAdmin ? ' Set them below.' : ' An administrator can set them here.'}
        </Alert>
      )}

      <Paper withBorder p="md">
        <Stack gap="sm">
          <Text fw={600}>Management address</Text>
          <Text size="xs" c="dimmed">
            Reachable IOS IP (or internal hostname). Distinct from the
            certificate FQDN used for ACME.
          </Text>
          <Group align="flex-end">
            <TextInput
              label="IOS management IP"
              placeholder="10.x.x.x"
              value={mgmtAddress}
              onChange={(event) => setMgmtAddress(event.currentTarget.value)}
              w={280}
              disabled={!canOperate}
            />
            <Button
              onClick={saveMgmt}
              loading={busy}
              disabled={!canOperate || !mgmtAddress.trim()}
            >
              Save
            </Button>
          </Group>
        </Stack>
      </Paper>

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Stack gap="sm">
            <Text fw={600}>Trustpoints</Text>
            <SimpleGrid cols={2}>
              <Field
                label="Active (bound)"
                value={<Code>{device.active_trustpoint ?? '—'}</Code>}
              />
              <Field label="Idle (next target)" value={<Code>{device.idle_trustpoint}</Code>} />
              <Field label="revocation-check" value={<Code>{device.revocation_check}</Code>} />
              <Field
                label="PKCS12 profile"
                value={
                  <Badge
                    size="sm"
                    variant="light"
                    color={device.pkcs12_profile === 'legacy' ? 'orange' : 'blue'}
                  >
                    {device.pkcs12_profile}
                  </Badge>
                }
              />
            </SimpleGrid>
            <Text size="xs" c="dimmed">
              Deployment imports into the idle trustpoint and verifies it before
              rebinding <Code>sip-ua</Code>. The active trustpoint keeps serving
              until that succeeds.
            </Text>
          </Stack>
        </Card>

        <Card withBorder>
          <Stack gap="sm">
            <Text fw={600}>Current certificate</Text>
            <SimpleGrid cols={2}>
              <Field label="Serial" value={<Code>{device.serial ?? '—'}</Code>} />
              <Field label="Status" value={device.cert_status ?? '—'} />
              <Field
                label="Expires"
                value={
                  device.not_after ? new Date(device.not_after).toLocaleString() : '—'
                }
              />
              <Field label="Chain" value={device.chain_issuer_cn ?? '—'} />
            </SimpleGrid>
            <Text size="xs" c="dimmed">
              Renews at {device.renewal_threshold} days remaining (includes this
              device's stable spread offset).
            </Text>
          </Stack>
        </Card>
      </SimpleGrid>

      {canAdmin && (
        <Card withBorder>
          <Stack gap="sm">
            <Text fw={600}>Inventory</Text>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="Management address"
                value={address}
                onChange={(e) => setAddress(e.currentTarget.value)}
              />
              <NumberInput label="SSH port" value={sshPort} onChange={setSshPort} min={1} />
              <TextInput
                label="Extra SANs"
                description="Comma-separated. The FQDN is always the primary name."
                value={sans}
                onChange={(e) => setSans(e.currentTarget.value)}
              />
              <Select
                label="PKCS12 profile"
                data={[
                  { value: 'modern', label: 'modern (AES)' },
                  { value: 'legacy', label: 'legacy (3DES, older IOS-XE)' },
                ]}
                value={p12Profile}
                onChange={(v) => setP12Profile(v || 'modern')}
              />
            </SimpleGrid>
            <Group>
              <Switch
                checked={enabled}
                onChange={(e) => setEnabled(e.currentTarget.checked)}
                label="Enabled"
                description="The scheduler skips disabled devices."
              />
              <Badge variant="light" color={device.has_host_key ? 'green' : 'yellow'}>
                {device.has_host_key ? 'host key pinned' : 'host key not pinned'}
              </Badge>
            </Group>
            <Group>
              <Button
                onClick={async () => {
                  setBusy(true);
                  try {
                    await api.updateDevice(device.fqdn, {
                      address,
                      ssh_port: Number(sshPort) || 22,
                      extra_sans: sans
                        .split(',')
                        .map((s) => s.trim())
                        .filter(Boolean),
                      pkcs12_profile: p12Profile,
                      enabled,
                    });
                    notifications.show({ color: 'green', message: 'Device updated' });
                    load();
                  } catch (err) {
                    notifications.show({ color: 'red', message: (err as Error).message });
                  } finally {
                    setBusy(false);
                  }
                }}
                loading={busy}
              >
                Save
              </Button>
              <Button
                color="red"
                variant="light"
                leftSection={<IconTrash size={16} />}
                onClick={async () => {
                  if (!confirm(`Delete ${device.fqdn} and its escrowed certificates?`)) return;
                  try {
                    await api.deleteDevice(device.fqdn);
                    navigate('/fleet');
                  } catch (err) {
                    notifications.show({ color: 'red', message: (err as Error).message });
                  }
                }}
              >
                Delete device
              </Button>
            </Group>
          </Stack>
        </Card>
      )}

      <Group>
        <Tooltip
          label="Requires the operator role"
          disabled={canOperate}
          withArrow
        >
          <Button
            leftSection={<IconCertificate size={16} />}
            onClick={issue}
            loading={busy}
            variant="light"
            disabled={!canOperate}
          >
            Issue now
          </Button>
        </Tooltip>
        <Tooltip
          label="Requires the operator role"
          disabled={canOperate}
          withArrow
        >
          <Button
            leftSection={<IconUpload size={16} />}
            onClick={openConfirm}
            loading={busy}
            disabled={!canOperate || !device.serial}
          >
            Deploy
          </Button>
        </Tooltip>
        <Button
          leftSection={<IconRefresh size={16} />}
          onClick={readLive}
          variant="subtle"
        >
          Read live state
        </Button>
        {canOperate && device.serial && (
          <Button
            variant="light"
            leftSection={<IconDownload size={16} />}
            onClick={async () => {
              try {
                await api.downloadPkcs12(device.fqdn);
              } catch (err) {
                notifications.show({ color: 'red', message: (err as Error).message });
              }
            }}
          >
            Download .p12
          </Button>
        )}
        {canAdmin && (
          <Button variant="light" leftSection={<IconKey size={16} />} onClick={openCreds}>
            Credentials
          </Button>
        )}
        {canAdmin && (
          <Tooltip
            label={
              device.has_mgmt_address
                ? 'Stores this gateway’s SSH public key with the device record. The container has no known_hosts, so later deploys refuse a changed key.'
                : 'Set a management IP first. The certificate FQDN is for ACME and is not reachable over SSH.'
            }
            withArrow
          >
            <Button
              variant="light"
              disabled={!device.has_mgmt_address}
              onClick={async () => {
                setBusy(true);
                try {
                  const preview = await api.previewHostKey(device.fqdn);
                  const ok =
                    preview.already_pinned ||
                    confirm(
                      `${preview.key_type} ${preview.fingerprint}\n\nPin this host key?` +
                        (preview.differs_from_pinned
                          ? '\n\nWARNING: a different key is already pinned.'
                          : ''),
                    );
                  if (!ok) return;
                  const pinned = await api.pinHostKey(device.fqdn);
                  notifications.show({
                    color: 'green',
                    message: `Pinned ${pinned.key_type} ${pinned.fingerprint}`,
                  });
                  load();
                } catch (err) {
                  notifications.show({ color: 'red', message: (err as Error).message });
                } finally {
                  setBusy(false);
                }
              }}
              loading={busy}
            >
              Pin SSH host key
            </Button>
          </Tooltip>
        )}
      </Group>

      {steps.length > 0 && (
        <Paper withBorder p="md">
          <Text fw={600} mb="xs">
            Last deployment
          </Text>
          <List size="sm" spacing={4}>
            {steps.map((step, index) => (
              <List.Item key={index}>
                <Text size="sm" ff="monospace" c={step.includes('ROLLED BACK') ? 'red' : undefined}>
                  {step}
                </Text>
              </List.Item>
            ))}
          </List>
        </Paper>
      )}

      {liveError && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} title="Could not reach the gateway">
          {liveError}
        </Alert>
      )}

      {live && (
        <Paper withBorder p="md">
          <Group justify="space-between" mb="sm">
            <Text fw={600}>Live device state</Text>
            <Badge color={live.matches_expected ? 'green' : 'yellow'} variant="light">
              {live.matches_expected ? 'matches expected' : 'drift'}
            </Badge>
          </Group>
          {live.note && (
            <Text size="sm" c="dimmed" mb="sm">
              {live.note}
            </Text>
          )}
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Trustpoint</Table.Th>
                <Table.Th>Subject</Table.Th>
                <Table.Th>Serial</Table.Th>
                <Table.Th>Expires</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {live.trustpoints.map((tp) => (
                <Table.Tr key={tp.label}>
                  <Table.Td>
                    <Group gap="xs">
                      <Code>{tp.label}</Code>
                      {tp.bound && (
                        <Tooltip label="Bound in sip-ua crypto signaling" withArrow>
                          <Badge size="xs" color="blue">
                            bound
                          </Badge>
                        </Tooltip>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    {tp.has_certificate ? (
                      tp.subject_cn
                    ) : tp.ca_subject_cn ? (
                      <Group gap="xs">
                        <Badge size="xs" variant="light" color="gray">
                          CA
                        </Badge>
                        <Text size="sm">{tp.ca_subject_cn}</Text>
                      </Group>
                    ) : (
                      '—'
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Code>{tp.serial ?? '—'}</Code>
                  </Table.Td>
                  <Table.Td>
                    {tp.validity_end ? new Date(tp.validity_end).toLocaleDateString() : '—'}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Paper>
      )}

      <Divider label="Certificate history" labelPosition="left" />
      <Paper withBorder>
        <Table.ScrollContainer minWidth={760}>
          <Table verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Serial</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Issued</Table.Th>
                <Table.Th>Expires</Table.Th>
                <Table.Th>Chain</Table.Th>
                <Table.Th>Trustpoint</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {device.certificates.map((cert) => (
                <Table.Tr key={cert.id}>
                  <Table.Td>
                    <Code>{cert.serial}</Code>
                  </Table.Td>
                  <Table.Td>
                    <Badge
                      size="sm"
                      variant="light"
                      color={
                        cert.status === 'deployed'
                          ? 'green'
                          : cert.status === 'failed'
                            ? 'red'
                            : 'gray'
                      }
                    >
                      {cert.status}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{new Date(cert.created_at).toLocaleDateString()}</Table.Td>
                  <Table.Td>{new Date(cert.not_after).toLocaleDateString()}</Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed">
                      {cert.chain_issuer_cn}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Code>{cert.target_trustpoint ?? '—'}</Code>
                  </Table.Td>
                </Table.Tr>
              ))}
              {device.certificates.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text size="sm" c="dimmed" ta="center" py="md">
                      Nothing issued yet.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>

      <Modal opened={confirmOpened} onClose={closeConfirm} title="Deploy certificate">
        <Stack>
          <Text size="sm">
            Import serial <Code>{device.serial}</Code> into{' '}
            <Code>{device.idle_trustpoint}</Code> on {device.fqdn}.
          </Text>
          <Switch
            checked={rebind}
            onChange={(event) => setRebind(event.currentTarget.checked)}
            label="Rebind sip-ua after verification"
            description={
              rebind
                ? 'Cuts over to the new trustpoint once the device confirms the certificate. Existing TLS connections to Webex will reconnect.'
                : 'Imports and verifies only. The active trustpoint keeps serving; useful ahead of a maintenance window.'
            }
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={closeConfirm}>
              Cancel
            </Button>
            <Button onClick={deploy} color={rebind ? 'blue' : 'gray'}>
              {rebind ? 'Deploy and cut over' : 'Stage only'}
            </Button>
          </Group>
        </Stack>
      </Modal>

      <Modal opened={credsOpened} onClose={closeCreds} title="SSH credentials">
        <Stack>
          <TextInput
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.currentTarget.value)}
          />
          <PasswordInput
            label="Password"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <PasswordInput
            label="Enable password (optional)"
            value={enablePassword}
            onChange={(e) => setEnablePassword(e.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={closeCreds}>
              Cancel
            </Button>
            <Button
              onClick={async () => {
                setBusy(true);
                try {
                  await api.setDeviceCredentials(
                    device.fqdn,
                    username,
                    password,
                    enablePassword || undefined,
                  );
                  notifications.show({ color: 'green', message: 'Credentials stored' });
                  closeCreds();
                  load();
                } catch (err) {
                  notifications.show({ color: 'red', message: (err as Error).message });
                } finally {
                  setBusy(false);
                }
              }}
              loading={busy}
              disabled={!username || !password}
            >
              Store
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
