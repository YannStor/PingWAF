import { apiClient } from './client'
import type { SystemStatusResponse, VersionResponse } from './types'

export const systemApi = {
  /** Unauthenticated build metadata endpoint. */
  version: () => apiClient.get<VersionResponse>('/version', { skipAuth: true }),
  /** Authenticated degraded-mode flags (plaintext gRPC, …). */
  status: () => apiClient.get<SystemStatusResponse>('/system/status'),
}

export default systemApi
