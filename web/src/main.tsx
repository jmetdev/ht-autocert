import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

import { createTheme, MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import { App } from './App';

const theme = createTheme({
  primaryColor: 'blue',
  defaultRadius: 'md',
  fontFamilyMonospace:
    'ui-monospace, SFMono-Regular, Menlo, Monaco, "Liberation Mono", monospace',
  headings: { fontWeight: '600' },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications position="top-right" />
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </MantineProvider>
  </StrictMode>,
);
