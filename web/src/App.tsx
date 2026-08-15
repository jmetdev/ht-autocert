import {
  AppShell,
  Burger,
  Center,
  Group,
  Loader,
  NavLink,
  Text,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconCertificate,
  IconHistory,
  IconRadar,
  IconLogout,
  IconServer2,
  IconUsers,
} from '@tabler/icons-react';
import { useCallback, useEffect, useState } from 'react';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { auth, clearToken, type Identity } from './lib/api';
import { WebexOrgProvider } from './lib/webexOrg';
import { OrgSelector } from './components/OrgSelector';
import { DeviceDetailPage } from './pages/DeviceDetail';
import { DiscoverPage } from './pages/Discover';
import { SignIn } from './pages/SignIn';
import { FleetPage } from './pages/Fleet';
import { RunsPage } from './pages/Runs';
import { SettingsPage } from './pages/Settings';

export function App() {
  const [opened, { toggle }] = useDisclosure();
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [checking, setChecking] = useState(true);
  const location = useLocation();

  const probe = useCallback(() => {
    setChecking(true);
    auth
      .me()
      .then(setIdentity)
      .catch(() => setIdentity({ authenticated: false }))
      .finally(() => setChecking(false));
  }, []);

  useEffect(probe, [probe]);

  if (checking) {
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  }

  if (!identity?.authenticated) return <SignIn onSignedIn={probe} />;

  const links = [
    { to: '/fleet', label: 'Fleet', icon: <IconServer2 size={16} /> },
    { to: '/discover', label: 'Discover', icon: <IconRadar size={16} /> },
    { to: '/runs', label: 'Run history', icon: <IconHistory size={16} /> },
    { to: '/settings', label: 'Tenants & CAs', icon: <IconUsers size={16} /> },
  ];

  return (
    <WebexOrgProvider>
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 240, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" gap="sm" wrap="nowrap">
          <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
          <IconCertificate size={22} />
          <Text fw={700}>ht-autocert</Text>
          <Text size="xs" c="dimmed" visibleFrom="md">
            Cisco IOS-XE voice gateway certificates
          </Text>
          <Group ml="auto" gap="sm" wrap="nowrap">
            <OrgSelector />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        <AppShell.Section grow>
          {links.map((link) => (
            <NavLink
              key={link.to}
              component={Link}
              to={link.to}
              label={link.label}
              leftSection={link.icon}
              active={location.pathname.startsWith(link.to)}
            />
          ))}
        </AppShell.Section>
        <AppShell.Section>
          <Text size="xs" c="dimmed" px="xs" truncate>
            {identity.email ?? identity.name}
          </Text>
          <Text size="xs" c="dimmed" px="xs" pb={4}>
            role: {identity.role ?? 'unknown'}
          </Text>
          <NavLink
            label="Sign out"
            color="red"
            leftSection={<IconLogout size={16} />}
            onClick={() => {
              auth.logout().catch(() => undefined);
              clearToken();
              setIdentity({ authenticated: false });
            }}
          />
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <Routes>
          <Route path="/" element={<Navigate to="/fleet" replace />} />
          <Route path="/fleet" element={<FleetPage />} />
          <Route
            path="/devices/:fqdn"
            element={<DeviceDetailPage identity={identity} />}
          />
          <Route
            path="/discover"
            element={<DiscoverPage identity={identity} />}
          />
          <Route path="/runs" element={<RunsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/fleet" replace />} />
        </Routes>
      </AppShell.Main>
    </AppShell>
    </WebexOrgProvider>
  );
}
