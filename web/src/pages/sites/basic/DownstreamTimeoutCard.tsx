import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Button } from '@/components/ui/Button'
import { useToast } from '@/components/ui/Toast'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import type { Site } from '@/api/types'

const MIN_SECONDS = 1
const MAX_SECONDS = 3600
const DEFAULT_SECONDS = 60

/**
 * Per-site downstream read/write budget. The value is applied after the
 * site's Location matches, so request headers and the request line still use
 * the listener default; that distinction is part of the hint.
 */
export function DownstreamTimeoutCard({ site }: { site: Site }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const saved = site.downstream_timeout_secs ?? DEFAULT_SECONDS
  const [draft, setDraft] = useState(String(saved))
  const [error, setError] = useState<string | null>(null)

  const parsed = Number(draft)
  const valid =
    /^\d+$/.test(draft.trim()) &&
    Number.isInteger(parsed) &&
    parsed >= MIN_SECONDS &&
    parsed <= MAX_SECONDS
  const dirty = valid && parsed !== saved

  const save = useMutation({
    mutationFn: (seconds: number) =>
      sitesApi.update(site.id, { downstream_timeout_secs: seconds }),
    onSuccess: () => {
      setError(null)
      toast.success(t('pages.basic.downstreamTimeout.saved'))
      void queryClient.invalidateQueries({
        queryKey: siteKeys.detail(site.id),
      })
    },
    onError: (e) => setError(errorMessage(e)),
  })

  return (
    <Card>
      <CardHeader
        title={t('pages.basic.downstreamTimeout.title')}
        description={t('pages.basic.downstreamTimeout.description')}
      />
      <CardBody className="space-y-4">
        <div className="flex flex-wrap items-end gap-4">
          <Input
            type="number"
            className="w-32 text-right"
            min={MIN_SECONDS}
            max={MAX_SECONDS}
            step={1}
            disabled={!canWrite || save.isPending}
            label={t('pages.basic.downstreamTimeout.label')}
            hint={t('pages.basic.downstreamTimeout.hint')}
            error={
              draft.trim() !== '' && !valid
                ? t('pages.basic.downstreamTimeout.range', {
                    min: MIN_SECONDS,
                    max: MAX_SECONDS,
                  })
                : undefined
            }
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value)
              setError(null)
            }}
          />
          <Button
            variant="primary"
            disabled={!canWrite || !dirty || save.isPending}
            loading={save.isPending}
            onClick={() => {
              if (!valid) {
                setError(
                  t('pages.basic.downstreamTimeout.range', {
                    min: MIN_SECONDS,
                    max: MAX_SECONDS,
                  }),
                )
                return
              }
              save.mutate(parsed)
            }}
          >
            {t('common.save')}
          </Button>
        </div>
        {error && <p className="text-[13px] text-danger">{error}</p>}
        <p className="text-xs leading-relaxed text-fg-subtle">
          {t('pages.basic.downstreamTimeout.headerNote')}
        </p>
      </CardBody>
    </Card>
  )
}
