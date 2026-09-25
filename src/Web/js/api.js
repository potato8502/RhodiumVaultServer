// Thin fetch wrapper for the server API. Every state-changing request carries the custom header the
// server requires as CSRF defence; the session cookie is HttpOnly and never visible to this code.

export class ApiError extends Error {
  constructor(status, code, retryAfterSeconds, data) {
    super(code || `http-${status}`);
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
    this.data = data;
  }
}

async function call(method, path, body) {
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-RVS-Request': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'network-error');
  }

  let data = null;
  const type = res.headers.get('content-type') || '';
  if (res.status !== 204 && type.includes('application/json')) {
    try { data = await res.json(); } catch { data = null; }
  }
  if (!res.ok) {
    const retry = parseInt(res.headers.get('retry-after') || '', 10);
    throw new ApiError(res.status, data?.error, Number.isFinite(retry) ? retry : undefined, data);
  }
  return data;
}

export const api = {
  status: () => call('GET', '/status'),
  prelogin: () => call('GET', '/prelogin'),
  setup: (body) => call('POST', '/setup', body),
  login: (authKey) => call('POST', '/login', { authKey }),
  logout: () => call('POST', '/logout'),
  getVault: () => call('GET', '/vault'),
  putVault: (expectedRevision, blob) => call('PUT', '/vault', { expectedRevision, blob }),
  changePassword: (body) => call('POST', '/change-password', body),
  history: () => call('GET', '/history'),
  historyItem: (rev) => call('GET', `/history/${rev}`),
  backup: () => call('GET', '/backup'),
};
