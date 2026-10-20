import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { useToast } from '@/components/ui/Toast'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import type { ResponseReplaceRule, Site } from '@/api/types'

/** Mirrors `MAX_RESPONSE_REPLACE_RULES` on the server. */
const MAX_RULES = 20
const MAX_PATTERN_BYTES = 512
const MAX_REPLACEMENT_BYTES = 2048

const DEFAULT_PATH = '^/.*'
const DEFAULT_STATUS_CODES = '200'

const byteLen = (s: string) => new TextEncoder().encode(s).length

/**
 * Site response-body replacement policy (`sites.response_replace`).
 *
 * ⚠️ 压缩响应（gzip/br）下替换不生效 —— 数据面的已知限制，卡片内固定提示。
 * 保存走 `PUT /api/v1/sites/{id}`；`rules: []` 视为清空，提交 `null`。
 */
export function ResponseReplaceCard({ site }: { site: Site }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [path, setPath] = useState(site.response_replace?.path ?? DEFAULT_PATH)
  const [statusCodes, setStatusCodes] = useState(
    (site.response_replace?.status_codes ?? [200]).join(', '),
  )
  const [rules, setRules] = useState<ResponseReplaceRule[]>(
    site.response_replace?.rules ?? [],
  )
  const [error, setError] = useState<string | null>(null)

  const dirty =
    path !== (site.response_replace?.path ?? DEFAULT_PATH) ||
    statusCodes !== (site.response_replace?.status_codes ?? [200]).join(', ') ||
    JSON.stringify(rules) !== JSON.stringify(site.response_replace?.rules ?? [])

  const save = useMutation({
    mutationFn: (payload: Parameters<typeof sitesApi.update>[1]) =>
      sitesApi.update(site.id, payload),
    onSuccess: () => {
      toast.success(t('common.saved'))
      void queryClient.invalidateQueries({ queryKey: siteKeys.detail(site.id) })
    },
    onError: (e) => setError(errorMessage(e)),
  })

  const submit = () => {
    setError(null)
    const trimmedPath = path.trim()
    if (trimmedPath) {
      try {
        new RegExp(trimmedPath)
      } catch {
        setError(t('errors.validation'))
        return
      }
    }
    const codes: number[] = []
    for (const part of statusCodes.split(/[,\s]+/).filter(Boolean)) {
      const code = Number(part)
      if (!Number.isInteger(code) || code < 100 || code > 599) {
        setError(t('errors.validation'))
        return
      }
      codes.push(code)
    }
    if (rules.length > MAX_RULES) {
      setError(t('errors.validation'))
      return
    }
    for (const rule of rules) {
      if (
        !rule.pattern ||
        byteLen(rule.pattern) > MAX_PATTERN_BYTES ||
        !rule.replacement ||
        byteLen(rule.replacement) > MAX_REPLACEMENT_BYTES ||
        rule.pattern.includes("'") ||
        rule.replacement.includes("'")
      ) {
        setError(t('errors.validation'))
        return
      }
      if (rule.is_regex) {
        try {
          new RegExp(rule.pattern)
        } catch {
          setError(t('errors.validation'))
          return
        }
      }
    }
    // An empty rule list clears the policy entirely → `null` in the API.
    const response_replace =
      rules.length === 0
        ? null
        : { path: trimmedPath || DEFAULT_PATH, status_codes: codes, rules }
    save.mutate({ response_replace })
  }

  const updateRule = (index: number, patch: Partial<ResponseReplaceRule>) => {
    setRules((rs) => rs.map((r, i) => (i === index ? { ...r, ...patch } : r)))
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.sites.responseReplace.title')}
        description={t('pages.sites.responseReplace.gzipHint')}
        action={
          <Button
            variant="primary"
            size="sm"
            loading={save.isPending}
            disabled={!canWrite || !dirty}
            onClick={submit}
          >
            {t('common.save')}
          </Button>
        }
      />
      <CardBody className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Input
            label={t('pages.sites.responseReplace.path')}
            value={path}
            placeholder={DEFAULT_PATH}
            className="pw-mono"
            disabled={!canWrite}
            onChange={(e) => setPath(e.target.value)}
          />
          <Input
            label={t('pages.sites.responseReplace.statusCodes')}
            value={statusCodes}
            placeholder={DEFAULT_STATUS_CODES}
            className="pw-mono"
            disabled={!canWrite}
            onChange={(e) => setStatusCodes(e.target.value)}
          />
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-fg-strong">
              {t('pages.sites.responseReplace.rules')}
              <Badge tone="neutral" size="sm" className="ml-2">
                {rules.length}/{MAX_RULES}
              </Badge>
            </span>
            <Button
              variant="secondary"
              size="sm"
              icon={<Plus weight="bold" className="h-4 w-4" />}
              disabled={!canWrite || rules.length >= MAX_RULES}
              onClick={() =>
                setRules((rs) => [...rs, { pattern: '', replacement: '', is_regex: false }])
              }
            >
              {t('pages.sites.responseReplace.addRule')}
            </Button>
          </div>

          {rules.length === 0 ? (
            <p className="rounded-md border border-line bg-recessed px-3 py-4 text-center text-[13px] text-fg-subtle">
              {t('pages.sites.responseReplace.empty')}
            </p>
          ) : (
            <div className="flex flex-col gap-2">
              {rules.map((rule, index) => (
                <div
                  key={index}
                  className="grid grid-cols-1 items-start gap-2 rounded-md border border-line p-2 sm:grid-cols-[1fr_1fr_auto]"
                >
                  <Input
                    aria-label={t('pages.sites.responseReplace.pattern')}
                    value={rule.pattern}
                    placeholder={t('pages.sites.responseReplace.pattern')}
                    className="pw-mono"
                    disabled={!canWrite}
                    onChange={(e) => updateRule(index, { pattern: e.target.value })}
                  />
                  <Input
                    aria-label={t('pages.sites.responseReplace.replacement')}
                    value={rule.replacement}
                    placeholder={t('pages.sites.responseReplace.replacement')}
                    className="pw-mono"
                    disabled={!canWrite}
                    onChange={(e) => updateRule(index, { replacement: e.target.value })}
                  />
                  <div className="flex items-center justify-between gap-2 sm:justify-end">
                    <Switch
                      size="sm"
                      checked={rule.is_regex}
                      disabled={!canWrite}
                      label={t('pages.sites.responseReplace.isRegex')}
                      onCheckedChange={(is_regex) => updateRule(index, { is_regex })}
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      className="hover:text-fg-danger"
                      aria-label={t('pages.sites.responseReplace.removeRule')}
                      disabled={!canWrite}
                      onClick={() => setRules((rs) => rs.filter((_, i) => i !== index))}
                      icon={<Trash weight="duotone" className="h-4 w-4" />}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {error && (
          <p
            role="alert"
            className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
          >
            {error}
          </p>
        )}
      </CardBody>
    </Card>
  )
}
