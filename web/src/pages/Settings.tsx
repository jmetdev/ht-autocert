import {
  Alert,
  Badge,
  Code,
  Group,
  Loader,
  Paper,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { IconInfoCircle } from '@tabler/icons-react';
import { useEffect, useState } from 'react';

import { api, type CAProfile, type Tenant } from '../lib/api';

export function SettingsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [profiles, setProfiles] = useState<CAProfile[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.tenants(), api.caProfiles()])
      .then(([t, p]) => {
        setTenants(t);
        setProfiles(p);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }

  return (
    <Stack>
      <Title order={2}>Tenants & certificate authorities</Title>

      <Alert color="blue" icon={<IconInfoCircle size={16} />}>
        This view is read-only. Tenants, CA profiles and credentials are managed
        through the CLI so that secrets are never entered into, or returned by,
        the web API — for example <Code>htac ca add</Code> and{' '}
        <Code>htac tenant set-credentials</Code>.
      </Alert>

      <Paper withBorder>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Tenant</Table.Th>
              <Table.Th>Domain suffix</Table.Th>
              <Table.Th>CA profile</Table.Th>
              <Table.Th>Renew at</Table.Th>
              <Table.Th>Devices</Table.Th>
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
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Code>{tenant.domain_suffix}</Code>
                </Table.Td>
                <Table.Td>{tenant.ca_profile_name ?? '—'}</Table.Td>
                <Table.Td>{tenant.renew_before_days}d</Table.Td>
                <Table.Td>{tenant.device_count}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Paper>

      <Title order={3} mt="md">
        Certificate authorities
      </Title>
      <Paper withBorder>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Directory</Table.Th>
              <Table.Th>Preferred chain</Table.Th>
              <Table.Th>Account</Table.Th>
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
                  <Badge
                    size="sm"
                    variant="light"
                    color={profile.registered ? 'green' : 'gray'}
                  >
                    {profile.registered ? 'registered' : 'not registered'}
                  </Badge>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Paper>
    </Stack>
  );
}
