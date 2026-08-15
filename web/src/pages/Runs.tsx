import {
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
import { useEffect, useState } from 'react';

import { api, type RunLog } from '../lib/api';

const STATUS_COLOR: Record<string, string> = {
  success: 'green',
  failed: 'red',
  skipped: 'gray',
  running: 'blue',
};

export function RunsPage() {
  const [runs, setRuns] = useState<RunLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .runs()
      .then(setRuns)
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
      <Title order={2}>Run history</Title>
      <Text size="sm" c="dimmed">
        Every issuance and deployment attempt, including skips. Correlate by run
        id to see one scheduled cycle end to end.
      </Text>
      <Paper withBorder>
        <Table.ScrollContainer minWidth={860}>
          <Table verticalSpacing="sm" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Started</Table.Th>
                <Table.Th>Run</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Gateway</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Detail</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {runs.map((run) => (
                <Table.Tr key={run.id}>
                  <Table.Td>
                    <Text size="xs">{new Date(run.started_at).toLocaleString()}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Code>{run.run_id}</Code>
                  </Table.Td>
                  <Table.Td>{run.action}</Table.Td>
                  <Table.Td>
                    <Text size="sm">{run.fqdn ?? '—'}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge
                      size="sm"
                      variant="light"
                      color={STATUS_COLOR[run.status] ?? 'gray'}
                    >
                      {run.status}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed" lineClamp={2}>
                      {run.detail}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
              {runs.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text size="sm" c="dimmed" ta="center" py="md">
                      Nothing has run yet.
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
