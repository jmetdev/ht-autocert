import {
  Alert,
  Button,
  Center,
  Divider,
  Group,
  Loader,
  Paper,
  PasswordInput,
  Stack,
  Text,
  Title,
} from '@mantine/core';
import { IconAlertTriangle, IconKey, IconShieldLock } from '@tabler/icons-react';
import { useEffect, useState } from 'react';

import { auth, setToken, type AuthConfig } from '../lib/api';

export function SignIn({ onSignedIn }: { onSignedIn: () => void }) {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [tokenValue, setTokenValue] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Surface the reason a redirect from /auth/callback bounced back here.
    const params = new URLSearchParams(window.location.search);
    const authError = params.get('auth_error');
    if (authError) {
      setError(authError);
      window.history.replaceState({}, '', window.location.pathname);
    }
    auth
      .config()
      .then(setConfig)
      .catch(() => setConfig({ webex_enabled: false, token_enabled: true }));
  }, []);

  const submitToken = (event: React.FormEvent) => {
    event.preventDefault();
    if (!tokenValue.trim()) return;
    setToken(tokenValue.trim());
    onSignedIn();
  };

  if (!config) {
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  }

  return (
    <Center h="100vh" p="md">
      <Paper withBorder shadow="md" p="xl" radius="md" w={440}>
        <Stack>
          <Group gap="xs">
            <IconShieldLock size={22} />
            <Title order={3}>ht-autocert</Title>
          </Group>

          {error && (
            <Alert color="red" icon={<IconAlertTriangle size={16} />} title="Sign-in failed">
              {error}
            </Alert>
          )}

          {config.webex_enabled ? (
            <>
              <Text size="sm" c="dimmed">
                Sign in with your Webex account. Access is restricted to
                approved users.
              </Text>
              <Button
                component="a"
                href="/auth/login"
                fullWidth
                size="md"
                color="teal"
              >
                Sign in with Webex
              </Button>
            </>
          ) : (
            <Text size="sm" c="dimmed">
              Webex sign-in is not configured on this server. Use the API token
              from <code>HTAC_API_TOKEN</code>.
            </Text>
          )}

          {config.token_enabled && (
            <>
              {config.webex_enabled && (
                <Divider
                  label={
                    <Button
                      variant="subtle"
                      size="compact-xs"
                      leftSection={<IconKey size={14} />}
                      onClick={() => setShowToken((v) => !v)}
                    >
                      Use an API token instead
                    </Button>
                  }
                  labelPosition="center"
                />
              )}
              {(showToken || !config.webex_enabled) && (
                <form onSubmit={submitToken}>
                  <Stack gap="sm">
                    <PasswordInput
                      label="API token"
                      placeholder="Bearer token"
                      value={tokenValue}
                      onChange={(event) => setTokenValue(event.currentTarget.value)}
                    />
                    <Button type="submit" variant="default" fullWidth>
                      Sign in with token
                    </Button>
                    <Text size="xs" c="dimmed">
                      Held for this browser session only; not written to
                      persistent storage.
                    </Text>
                  </Stack>
                </form>
              )}
            </>
          )}
        </Stack>
      </Paper>
    </Center>
  );
}
