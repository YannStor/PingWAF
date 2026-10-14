import {
  getAuthToken,
  getRefreshToken,
  useAuthStore,
} from '@/stores/authStore'

/**
 * REST base path. The frontend is served from the same origin as the control
 * plane, so a relative prefix works in development (vite proxy) and production
 * (`serve_frontend` fallback) alike.
 */
export const BASE_URL = '/api/v1'

/** Error codes emitted by `pingwaf-server::api::error::ApiError::code`. */
export type ApiErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'unprocessable_entity'
  | 'not_implemented'
  | 'internal_error'
  | 'network_error'

/** Wire shape of the shared `{"error": {"code", "message"}}` envelope. */
interface ErrorEnvelope {
  error?: { code?: string; message?: string }
  code?: string
  message?: string
}

export class ApiError extends Error {
  status: number
  code: ApiErrorCode | string
  /** True when the request never reached the server (DNS/TLS/offline). */
  networkError: boolean

  constructor(
    message: string,
    status: number,
    code: ApiErrorCode | string = 'internal_error',
    networkError = false,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.networkError = networkError
  }
}

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
  /**
   * Query string parameters. Typed as `object` so the generated request
   * interfaces (`RangeQuery`, `LogQueryParams`, …) can be passed straight
   * through; `undefined`, `null` and `''` values are dropped, arrays are
   * repeated once per element.
   */
  query?: object
  /** Skip Authorization header injection and 401 refresh handling. */
  skipAuth?: boolean
}

function buildUrl(path: string, query?: RequestOptions['query']): string {
  const url = `${BASE_URL}${path.startsWith('/') ? path : `/${path}`}`
  if (!query) return url
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query as Record<string, unknown>)) {
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null && item !== '') {
          params.append(key, String(item))
        }
      }
      continue
    }
    params.append(key, String(value))
  }
  const qs = params.toString()
  return qs ? `${url}?${qs}` : url
}

function parseEnvelope(raw: unknown): { code?: string; message?: string } {
  if (!raw || typeof raw !== 'object') return {}
  const body = raw as ErrorEnvelope
  const inner = body.error
  if (inner && typeof inner === 'object') {
    return { code: inner.code, message: inner.message }
  }
  return { code: body.code, message: body.message }
}

/* ────────────────────────────────────────────────────────────────
   Access-token refresh (single flight)
   ──────────────────────────────────────────────────────────────── */

let refreshInFlight: Promise<string | null> | null = null

/**
 * Exchanges the stored refresh token for a fresh access token. Concurrent 401s
 * share a single in-flight request so the refresh endpoint is hit at most once.
 */
export function refreshAccessToken(): Promise<string | null> {
  if (refreshInFlight) return refreshInFlight

  const refreshToken = getRefreshToken()
  if (!refreshToken) return Promise.resolve(null)

  refreshInFlight = (async () => {
    try {
      const res = await fetch(`${BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      })
      if (!res.ok) return null
      const data = (await res.json()) as {
        access_token?: string
        refresh_token?: string
      }
      if (!data.access_token) return null
      useAuthStore
        .getState()
        .setTokens(data.access_token, data.refresh_token ?? refreshToken)
      return data.access_token
    } catch {
      return null
    }
  })()

  void refreshInFlight.finally(() => {
    refreshInFlight = null
  })
  return refreshInFlight
}

/* ────────────────────────────────────────────────────────────────
   Core request
   ──────────────────────────────────────────────────────────────── */

async function send(
  path: string,
  options: RequestOptions,
  token: string | null,
): Promise<Response> {
  const { body, query, skipAuth: _skipAuth, headers, ...rest } = options

  // FormData (multipart uploads) passes through untouched: the browser must
  // generate the Content-Type with its own multipart boundary.
  const isForm = body instanceof FormData
  const finalHeaders = new Headers(headers)
  if (body !== undefined && !isForm && !finalHeaders.has('Content-Type')) {
    finalHeaders.set('Content-Type', 'application/json')
  }
  finalHeaders.set('Accept', 'application/json')
  if (token) finalHeaders.set('Authorization', `Bearer ${token}`)

  return fetch(buildUrl(path, query), {
    ...rest,
    headers: finalHeaders,
    body: body === undefined ? undefined : isForm ? (body as FormData) : JSON.stringify(body),
  })
}

async function readError(response: Response): Promise<ApiError> {
  let message = `Request failed (${response.status})`
  let code: string = 'internal_error'
  try {
    const parsed = parseEnvelope(await response.json())
    if (parsed.message) message = parsed.message
    if (parsed.code) code = parsed.code
  } catch {
    /* non-JSON error body — keep the generic message */
  }
  if (code === 'internal_error' && response.status < 500) {
    code = response.status === 401 ? 'unauthorized'
      : response.status === 403 ? 'forbidden'
      : response.status === 404 ? 'not_found'
      : response.status === 409 ? 'conflict'
      : response.status === 501 ? 'not_implemented'
      : 'bad_request'
  }
  return new ApiError(message, response.status, code)
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { skipAuth } = options

  let response: Response
  try {
    response = await send(path, options, skipAuth ? null : getAuthToken())
  } catch (err) {
    throw new ApiError(
      err instanceof Error ? err.message : 'Network request failed',
      0,
      'network_error',
      true,
    )
  }

  // Expired access token → try a silent refresh exactly once.
  if (response.status === 401 && !skipAuth) {
    const fresh = await refreshAccessToken()
    if (fresh) {
      try {
        response = await send(path, options, fresh)
      } catch (err) {
        throw new ApiError(
          err instanceof Error ? err.message : 'Network request failed',
          0,
          'network_error',
          true,
        )
      }
    }
  }

  if (!response.ok) {
    const apiError = await readError(response)
    if (apiError.status === 401 && !skipAuth) {
      // Session is truly over — drop credentials so the router redirects.
      useAuthStore.getState().logout()
    }
    throw apiError
  }

  if (response.status === 204) return undefined as T
  const text = await response.text()
  if (!text) return undefined as T
  try {
    return JSON.parse(text) as T
  } catch {
    return text as unknown as T
  }
}

export const apiClient = {
  get: <T>(path: string, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'GET' }),
  post: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'POST', body }),
  put: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'PUT', body }),
  patch: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'PATCH', body }),
  delete: <T>(path: string, options?: RequestOptions) =>
    request<T>(path, { ...options, method: 'DELETE' }),
}

/** Kept for existing call sites that imported the default/named `api`. */
export const api = apiClient

export default apiClient
