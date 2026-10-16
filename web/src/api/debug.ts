import { BASE_URL, ApiError, refreshAccessToken } from './client'
import { getAuthToken, useAuthStore } from '@/stores/authStore'
import type { MemorySnapshot } from './types'

/**
 * Debug / performance diagnostics — `/api/v1/debug/pprof/*` (admin only).
 *
 * The CPU profile and flamegraph endpoints capture while you wait: the server
 * holds the connection open for `seconds` and then streams the artifact back
 * (Content-Disposition attachment for the profile, `image/svg+xml` for the
 * flamegraph), so callers download the body as a Blob.
 *
 * Error cases mirrored from `pingwaf-server/src/api/debug.rs`:
 * - `501 Not Implemented` — CPU capture needs Linux (memory snapshot works).
 * - `409 Conflict` — another profiling session is already running.
 * - `403 Forbidden` — non-admin callers.
 */

/** Must match `pingwaf_pprof::MAX_SECONDS` (currently 5); the server clamps to 1..=MAX. */
export const PPROF_MAX_SECONDS = 5
export const PPROF_DEFAULT_SECONDS = 5

/** Shared request runner: auth header + single 401 token-refresh retry. */
async function request(path: string, query?: Record<string, unknown>): Promise<Response> {
  let token = getAuthToken()
  let response: Response
  for (let attempt = 0; ; attempt++) {
    try {
      response = await fetch(`${BASE_URL}${path}${query ? `?${new URLSearchParams(
        Object.entries(query)
          .filter(([, v]) => v !== undefined && v !== null && v !== '')
          .map(([k, v]) => [k, String(v)]),
      )}` : ''}`, {
        headers: token ? { Authorization: `Bearer ${token}`, Accept: '*/*' } : { Accept: '*/*' },
      })
    } catch (err) {
      throw new ApiError(
        err instanceof Error ? err.message : 'Network request failed',
        0,
        'network_error',
        true,
      )
    }
    if (response.status === 401 && attempt === 0) {
      const fresh = await refreshAccessToken()
      if (fresh) {
        token = fresh
        continue
      }
      useAuthStore.getState().logout()
    }
    break
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = (await response.json()) as { error?: { message?: string } }
      if (body.error?.message) message = body.error.message
    } catch {
      /* non-JSON body — keep the generic message */
    }
    throw new ApiError(message, response.status)
  }
  return response
}

async function download(path: string, query?: Record<string, unknown>): Promise<Blob> {
  const response = await request(path, query)
  return response.blob()
}

/** Triggers a browser download for a Blob using its Content-Disposition filename. */
function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** CPU profile (gzip pprof protobuf) — consumable by `go tool pprof`. */
export async function downloadCpuProfile(
  seconds: number,
  selfload = false,
): Promise<void> {
  const blob = await download('/debug/pprof/profile', {
    seconds: Math.min(PPROF_MAX_SECONDS, Math.max(1, seconds)),
    selfload,
  })
  saveBlob(blob, 'pingwaf-cpu.pb.gz')
}

/** SVG flamegraph of the capture window. */
export async function downloadFlamegraph(
  seconds: number,
  selfload = false,
): Promise<void> {
  const blob = await download('/debug/pprof/flamegraph', {
    seconds: Math.min(PPROF_MAX_SECONDS, Math.max(1, seconds)),
    selfload,
  })
  saveBlob(blob, 'pingwaf-flamegraph.svg')
}

/** JSON memory snapshot — no capture window, answers immediately. */
export async function downloadMemorySnapshot(): Promise<void> {
  const blob = await download('/debug/pprof/memory')
  saveBlob(blob, 'pingwaf-memory.json')
}

/**
 * JSON memory snapshot as a parsed object (mirror of `downloadMemorySnapshot`).
 * Field scopes: `rss_bytes`/`virtual_bytes` are this process's own footprint
 * (`process_memory_scope: "process"`); `used_memory_bytes`/`total_memory_bytes`
 * are the **host's** RAM (`used_memory_scope: "system"`).
 */
export async function fetchMemorySnapshot(): Promise<MemorySnapshot> {
  const response = await request('/debug/pprof/memory')
  return (await response.json()) as MemorySnapshot
}

/* ── CPU summary ─────────────────────────────────────────────────────── */

/** One hot frame from the last CPU capture (backend truncates names to 52 chars). */
export interface CpuTopFrame {
  name: string
  samples: number
  /** Fraction of total samples, 0..1. */
  share: number
}

export type CpuCaptureStatus = 'normal' | 'high_load' | 'idle' | 'platform_limited'

/** `last_capture` — null before the first capture on this boot. */
export interface CpuCaptureSummaryInfo {
  total_samples: number
  frequency: number
  window_secs: number
  cpu_secs: number
  /** Process CPU usage across the window, 0..1. */
  process_cpu_fraction: number
  status: CpuCaptureStatus
  top_frames: CpuTopFrame[]
  collected_at_ms: number
}

export interface CpuProfilingSummary {
  live: {
    process_cpu_percent: number
    host_cpu_percent: number
    cores: number
    collected_at_ms: number
    profiling: {
      total_started: number
      last: {
        finished_at_ms: number
        duration_secs: number
        outcome: string
      } | null
    } | null
  }
  last_capture: CpuCaptureSummaryInfo | null
}

/**
 * Server-side CPU summary — `GET /debug/pprof/cpu/summary` (admin only).
 * Pass `capture: true` to run a blocking ~5s capture first; the response then
 * includes the fresh `last_capture` (this also respects `selfload`).
 */
export async function fetchCpuSummary(
  opts?: { capture?: boolean; selfload?: boolean },
): Promise<CpuProfilingSummary> {
  const response = await request('/debug/pprof/cpu/summary', {
    capture: opts?.capture ? 'true' : undefined,
    selfload: opts?.selfload ? 'true' : undefined,
  })
  return (await response.json()) as CpuProfilingSummary
}

export const debugKeys = {
  all: ['debug'] as const,
  memory: () => [...debugKeys.all, 'memory'] as const,
  cpuSummary: () => [...debugKeys.all, 'cpuSummary'] as const,
}

/** Convenience alias used by pages. */
export const debugApi = { memory: fetchMemorySnapshot }
