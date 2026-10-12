import { apiClient } from './client'
import {
  createPasskey,
  getAssertion,
  type CreationOptionsJson,
  type RequestOptionsJson,
} from '@/lib/webauthn'
import type { LoginResponse, PasskeySummary } from './types'

/**
 * Passkeys bound to the signed-in dashboard account.
 *
 * `register` and `login` drive the whole ceremony: they ask the control plane
 * for options, hand them to the authenticator, and post the result back, so a
 * caller cannot leave a half-finished ceremony behind.
 */
export const passkeysApi = {
  list: () => apiClient.get<PasskeySummary[]>('/auth/passkeys'),

  rename: (id: string, name: string) =>
    apiClient.patch<PasskeySummary>(`/auth/passkeys/${id}`, { name }),

  remove: (id: string) => apiClient.delete<void>(`/auth/passkeys/${id}`),

  /** Binds a new authenticator to the current account. */
  register: async (name: string): Promise<PasskeySummary | undefined> => {
    const options = await apiClient.post<CreationOptionsJson>(
      '/auth/passkey/register/begin',
    )
    const credential = await createPasskey(options, name)
    return apiClient.post<PasskeySummary | undefined>(
      '/auth/passkey/register/finish',
      credential,
    )
  },

  /**
   * Signs in with any passkey this deployment knows. Unauthenticated: the
   * credential itself identifies the account.
   */
  login: async (): Promise<LoginResponse> => {
    const options = await apiClient.post<RequestOptionsJson>(
      '/auth/passkey/login/begin',
      undefined,
      { skipAuth: true },
    )
    const assertion = await getAssertion(options)
    return apiClient.post<LoginResponse>(
      '/auth/passkey/login/finish',
      assertion,
      { skipAuth: true },
    )
  },

  /** Master switch (admin): whether passkey login/registration is offered. */
  getSettings: () => apiClient.get<{ enabled: boolean }>('/settings/passkeys'),

  updateSettings: (enabled: boolean) =>
    apiClient.put<{ enabled: boolean }>('/settings/passkeys', { enabled }),
}

export const passkeyKeys = {
  all: ['passkeys'] as const,
  list: () => [...passkeyKeys.all, 'list'] as const,
  settings: () => [...passkeyKeys.all, 'settings'] as const,
}

export default passkeysApi
