import { useEffect, useId, useSyncExternalStore, type ReactNode } from 'react'
import { useBlocker } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'

/**
 * Guards against silently losing unsaved form changes.
 *
 * Two layers:
 * - In-app navigation (sidebar links, browser back): react-router `useBlocker`
 *   (available — the app uses `createBrowserRouter`, a data router) shows a
 *   `ConfirmDialog` with "leave / stay" actions.
 * - Closing/reloading the tab: the `beforeunload` browser prompt.
 *
 * Forms with an independent `dirty` state call `useRegisterUnsaved(dirty)` and
 * the page root aggregates them with `useUnsavedGuard(useAnyUnsaved())`
 * (see `SettingsPage`, where multiple section cards live on one route). Pages
 * with a single form call `useUnsavedGuard(dirty)` directly and render the
 * returned dialog node.
 */

/* ── Module-level registry for aggregated (page-level) guards ─────────── */

const dirtyForms = new Set<string>()
const listeners = new Set<() => void>()

function setRegistered(id: string, dirty: boolean) {
  const had = dirtyForms.has(id)
  if (dirty && !had) {
    dirtyForms.add(id)
    listeners.forEach((l) => l())
  } else if (!dirty && had) {
    dirtyForms.delete(id)
    listeners.forEach((l) => l())
  }
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Registers a form's dirty flag into the shared page-level registry. */
export function useRegisterUnsaved(dirty: boolean): void {
  const id = useId()
  useEffect(() => {
    setRegistered(id, dirty)
    return () => setRegistered(id, false)
  }, [id, dirty])
}

/** True while any form registered via `useRegisterUnsaved` is dirty. */
export function useAnyUnsaved(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => dirtyForms.size > 0,
    () => false,
  )
}

/* ── The guard itself ─────────────────────────────────────────────────── */

export function useUnsavedGuard(dirty: boolean): ReactNode {
  const { t } = useTranslation()
  const blocker = useBlocker(dirty)

  // Bottom line: tab close / reload / hard navigation outside the router.
  useEffect(() => {
    if (!dirty) return
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      // Chrome requires returnValue to show the prompt.
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => window.removeEventListener('beforeunload', onBeforeUnload)
  }, [dirty])

  if (blocker.state !== 'blocked') return null

  return (
    <ConfirmDialog
      open
      tone="primary"
      title={t('common.unsavedGuard.title')}
      description={t('common.unsavedGuard.description')}
      confirmLabel={t('common.unsavedGuard.leave')}
      cancelLabel={t('common.unsavedGuard.stay')}
      onClose={blocker.reset}
      onConfirm={blocker.proceed}
    />
  )
}
