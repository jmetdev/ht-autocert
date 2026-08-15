/**
 * The Webex organisation the console is currently looking at.
 *
 * Each client is a separate Webex org, so almost every Control Hub read is
 * org-scoped. Holding the selection in one place keeps the toolbar, the
 * Discover page and any future org-scoped view from disagreeing about which
 * customer is on screen -- and makes the current org visible at all times,
 * which matters when the same button imports into a different tenant depending
 * on what is selected.
 */

import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';

import { api, type WebexOrg } from './api';

const STORAGE_KEY = 'htac.webexOrgId';

interface WebexOrgState {
  orgs: WebexOrg[];
  orgId: string | null;
  org: WebexOrg | null;
  setOrgId: (id: string | null) => void;
  loading: boolean;
  /** Why the org list is unavailable, if it is. Shown rather than swallowed. */
  error: string | null;
  reload: () => void;
}

const Context = createContext<WebexOrgState | null>(null);

export function WebexOrgProvider({ children }: { children: ReactNode }) {
  const [orgs, setOrgs] = useState<WebexOrg[]>([]);
  const [orgId, setOrgIdState] = useState<string | null>(() =>
    localStorage.getItem(STORAGE_KEY),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .webexOrgs()
      .then((list) => {
        setOrgs(list);
        setOrgIdState((current) => {
          // Drop a stored selection the token can no longer see, rather than
          // leaving a stale ID that would 403 on the next import.
          if (current && list.some((o) => o.org_id === current)) return current;
          const fallback = list.length === 1 ? list[0].org_id : null;
          if (fallback) localStorage.setItem(STORAGE_KEY, fallback);
          else localStorage.removeItem(STORAGE_KEY);
          return fallback;
        });
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(reload, [reload]);

  const setOrgId = useCallback((id: string | null) => {
    setOrgIdState(id);
    if (id) localStorage.setItem(STORAGE_KEY, id);
    else localStorage.removeItem(STORAGE_KEY);
  }, []);

  const org = orgs.find((o) => o.org_id === orgId) ?? null;

  return (
    <Context.Provider
      value={{ orgs, orgId, org, setOrgId, loading, error, reload }}
    >
      {children}
    </Context.Provider>
  );
}

export function useWebexOrg(): WebexOrgState {
  const value = useContext(Context);
  if (!value) throw new Error('useWebexOrg must be used inside WebexOrgProvider');
  return value;
}
