import { apiClient } from './client'
import type {
  Agent,
  AgentCommandRequest,
  AgentCommandResult,
  AgentEnrollRequest,
  AgentEnrollResponse,
  AgentListQuery,
  AgentSamplesQuery,
  HostSample,
  Page,
} from './types'

/**
 * Agents — `/api/v1/agents`.
 *
 * An agent appears in the inventory the first time it connects with an agent
 * API key, so enrolling a node means handing the operator a key and the command
 * that uses it: `POST /agents/enroll` mints that key and returns the ready-to-run
 * command lines.
 */
export const agentsApi = {
  list: (query: AgentListQuery = {}) =>
    apiClient.get<Page<Agent>>('/agents', { query: { page_size: 200, ...query } }),

  /**
   * Host probe history, newest first. The agent samples every 5 seconds but the
   * control plane persists one sample per minute and keeps a day of it, so
   * `page_size` is the window size here.
   */
  samples: (id: string, query: AgentSamplesQuery = {}) =>
    apiClient.get<Page<HostSample>>(`/agents/${id}/samples`, {
      query: { page_size: 200, ...query },
    }),

  remove: (id: string) => apiClient.delete<void>(`/agents/${id}`),

  /** Mints an agent key and returns the command that brings a node online. */
  enroll: (data: AgentEnrollRequest = {}) =>
    apiClient.post<AgentEnrollResponse>('/agents/enroll', data),

  /**
   * Queues a command for the agent. Answers `202` immediately; `delivered` is
   * true when the agent holds an open stream, otherwise it is `queued` and sent
   * on the next heartbeat.
   */
  sendCommand: (id: string, data: AgentCommandRequest) =>
    apiClient.post<AgentCommandResult>(`/agents/${id}/commands`, data),
}

/** Status ordering used for the summary counters. */
export const AGENT_STATUSES = ['online', 'degraded', 'offline'] as const

export function countByStatus(agents: Agent[]): Record<string, number> {
  return agents.reduce<Record<string, number>>((acc, agent) => {
    acc[agent.status] = (acc[agent.status] ?? 0) + 1
    return acc
  }, {})
}

export const agentKeys = {
  all: ['agents'] as const,
  list: (query?: AgentListQuery) => [...agentKeys.all, 'list', query ?? {}] as const,
  detail: (id: string) => [...agentKeys.all, 'detail', id] as const,
  samples: (id: string, query?: AgentSamplesQuery) =>
    [...agentKeys.all, 'samples', id, query ?? {}] as const,
}

export default agentsApi
