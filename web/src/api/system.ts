import { apiClient } from './client'
import type { VersionResponse } from './types'

/** Unauthenticated build metadata endpoint. */
export const systemApi = {
  version: () => apiClient.get<VersionResponse>('/version', { skipAuth: true }),
}

export default systemApi
