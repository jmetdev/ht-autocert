import { Badge, Group, Select, Text, Tooltip } from '@mantine/core';
import { IconBuilding, IconAlertTriangle } from '@tabler/icons-react';

import { useWebexOrg } from '../lib/webexOrg';

/**
 * Toolbar picker for the active Webex organisation.
 *
 * Shows which tenant an org is linked to, because "Higley Unified" in Control
 * Hub and the `higley` tenant here are different records that have to be
 * deliberately mapped -- an unlinked org can be browsed but not imported into.
 */
export function OrgSelector() {
  const { orgs, orgId, org, setOrgId, loading, error } = useWebexOrg();

  if (error) {
    return (
      <Tooltip label={error} multiline w={320}>
        <Group gap={6} c="dimmed">
          <IconAlertTriangle size={16} />
          <Text size="xs">Control Hub unavailable</Text>
        </Group>
      </Tooltip>
    );
  }

  return (
    <Group gap="xs" wrap="nowrap">
      <Select
        aria-label="Webex organisation"
        placeholder={loading ? 'Loading organisations…' : 'Select organisation'}
        leftSection={<IconBuilding size={16} />}
        data={orgs.map((o) => ({
          value: o.org_id,
          label: o.tenant_slug ? `${o.display_name} (${o.tenant_slug})` : o.display_name,
        }))}
        value={orgId}
        onChange={setOrgId}
        disabled={loading}
        searchable
        clearable
        nothingFoundMessage="No matching organisation"
        w={320}
        size="xs"
        comboboxProps={{ width: 380, position: 'bottom-start' }}
      />
      {org && !org.tenant_slug && (
        <Tooltip label="This organisation is not linked to a tenant yet. Link it in Settings before importing.">
          <Badge size="xs" color="yellow" variant="light">
            unlinked
          </Badge>
        </Tooltip>
      )}
    </Group>
  );
}
