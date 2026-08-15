/**
 * API client.
 *
 * The bearer token is held in sessionStorage rather than localStorage, so it
 * does not survive the browser session — this is an operations console with
 * authority to reissue and deploy certificates across the fleet.
 */

const TOKEN_KEY = 'htac.token';

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const response = await fetch(path, {
    ...init,
    // Send the Webex session cookie. The bearer token is only attached when a
    // token was entered explicitly (automation / no-Webex deployments).
    credentials: 'same-origin',
    headers: {
      ...(init.headers ?? {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* keep the generic message */
    }
    if (response.status === 401) clearToken();
    throw new ApiError(detail, response.status);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export type DeviceState = 'ok' | 'renew_due' | 'expired' | 'missing';

export interface Device {
  id: number;
  hostname: string;
  fqdn: string;
  mgmt_address: string;
  tenant_slug: string;
  tenant_name: string;
  enabled: boolean;
  trustpoint_a: string;
  trustpoint_b: string;
  active_trustpoint: string | null;
  idle_trustpoint: string;
  pkcs12_profile: string;
  revocation_check: string;
  has_credentials: boolean;
  days_remaining: number | null;
  not_after: string | null;
  chain_issuer_cn: string | null;
  serial: string | null;
  cert_status: string | null;
  renewal_threshold: number;
  renewal_due: boolean;
  state: DeviceState;
}

export interface Certificate {
  id: number;
  serial: string;
  subject_cn: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  chain_issuer_cn: string;
  status: string;
  pkcs12_profile: string;
  target_trustpoint: string | null;
  created_at: string;
  deployed_at: string | null;
  days_remaining: number;
}

export interface DeviceDetail extends Device {
  certificates: Certificate[];
}

export interface Trustpoint {
  label: string;
  subject_cn: string | null;
  ca_subject_cn: string | null;
  serial: string | null;
  validity_end: string | null;
  has_certificate: boolean;
  bound: boolean;
}

export interface LiveState {
  fqdn: string;
  bound_trustpoint: string | null;
  trustpoints: Trustpoint[];
  matches_expected: boolean;
  note: string | null;
}

export interface Summary {
  devices: number;
  tenants: number;
  ok: number;
  renew_due: number;
  expired: number;
  missing: number;
  expiring_within_14d: number;
  last_run_at: string | null;
  last_run_status: string | null;
  next_run_at: string | null;
  scheduler_enabled: boolean;
}

export interface Tenant {
  id: number;
  slug: string;
  name: string;
  domain_suffix: string;
  renew_before_days: number;
  enabled: boolean;
  ca_profile_name: string | null;
  device_count: number;
  webex_org_id: string | null;
  webex_org_name: string | null;
}

export interface CAProfile {
  id: number;
  name: string;
  directory_url: string;
  contact_email: string;
  preferred_chain: string | null;
  enabled: boolean;
  uses_eab: boolean;
  registered: boolean;
}

export interface RunLog {
  id: number;
  run_id: string;
  action: string;
  status: string;
  detail: string | null;
  started_at: string;
  finished_at: string | null;
  fqdn: string | null;
}

export interface ActionResult {
  fqdn: string;
  status: string;
  detail: string;
  steps: string[];
}

export interface AuthConfig {
  webex_enabled: boolean;
  token_enabled: boolean;
}

export type Role = 'viewer' | 'operator' | 'admin';

export interface Identity {
  authenticated: boolean;
  method?: 'webex' | 'token';
  email?: string | null;
  name?: string | null;
  role?: Role;
  reason?: string;
}

const ROLE_ORDER: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

export function hasRole(identity: Identity | null, required: Role): boolean {
  if (!identity?.role) return false;
  return ROLE_ORDER[identity.role] >= ROLE_ORDER[required];
}

export interface WebexOrg {
  org_id: string;
  display_name: string;
  tenant_slug: string | null;
}

export interface WebexCandidate {
  name: string;
  trunk_id: string;
  trunk_type: string;
  device_type: string | null;
  location: string | null;
  status: string | null;
  in_use: boolean;
  address: string | null;
  fqdn: string | null;
  proposed_fqdn: string | null;
  /** Where proposed_fqdn came from: Webex itself, or the tenant suffix. */
  fqdn_source: 'webex' | 'derived' | 'none';
  importable: boolean;
  reason: string | null;
}

export interface WebexImport {
  tenant: string;
  org_id: string;
  org_name: string | null;
  found: number;
  imported: number;
  applied: boolean;
  candidates: WebexCandidate[];
}

export const auth = {
  config: () => request<AuthConfig>('/auth/config'),
  me: () => request<Identity>('/auth/me'),
  logout: () => request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),
};

export const api = {
  summary: () => request<Summary>('/api/summary'),
  devices: (params?: { tenant?: string; state?: string }) => {
    const query = new URLSearchParams();
    if (params?.tenant) query.set('tenant', params.tenant);
    if (params?.state) query.set('state', params.state);
    const suffix = query.toString() ? `?${query}` : '';
    return request<Device[]>(`/api/devices${suffix}`);
  },
  device: (fqdn: string) => request<DeviceDetail>(`/api/devices/${fqdn}`),
  liveState: (fqdn: string) => request<LiveState>(`/api/devices/${fqdn}/live`),
  tenants: () => request<Tenant[]>('/api/tenants'),
  caProfiles: () => request<CAProfile[]>('/api/ca-profiles'),
  runs: (fqdn?: string) =>
    request<RunLog[]>(`/api/runs${fqdn ? `?fqdn=${fqdn}` : ''}`),
  issue: (fqdn: string, force = false) =>
    request<ActionResult>(`/api/devices/${fqdn}/issue?force=${force}`, {
      method: 'POST',
    }),
  webexOrgs: () => request<WebexOrg[]>('/api/webex/orgs'),
  webexImport: (tenant: string, orgId: string, apply: boolean) => {
    const query = new URLSearchParams({
      tenant,
      org_id: orgId,
      apply: String(apply),
    });
    return request<WebexImport>(`/api/webex/import?${query}`, { method: 'POST' });
  },
  linkWebexOrg: (slug: string, orgId: string, orgName: string) => {
    const query = new URLSearchParams({ org_id: orgId, org_name: orgName });
    return request<Tenant>(`/api/tenants/${slug}/webex-org?${query}`, {
      method: 'PUT',
    });
  },
  deploy: (fqdn: string, rebind = true) =>
    request<ActionResult>(`/api/devices/${fqdn}/deploy?rebind=${rebind}`, {
      method: 'POST',
    }),
};
