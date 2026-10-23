import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Sliders,
  Plus,
  PencilSimple,
  Trash,
  ArrowClockwise,
  ArrowUp,
  ArrowDown,
  X,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Tabs } from '@/components/ui/Tabs'
import { Textarea } from '@/components/ui/Textarea'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { rewriteApi, rewriteKeys } from '@/api/rewrite'
import { useCanWrite, useSiteDetail } from '@/hooks'
import { ResponseReplaceCard } from './ResponseReplaceCard'
import {
  EXPRESSION_FIELDS,
  EXPRESSION_OPERATORS,
  buildExpression,
  parseExpression,
  type ExpressionCombinator,
  type ExpressionCondition,
  type ExpressionOperator,
} from '@/lib/expression'
import {
  REWRITE_DIRECTIONS,
  REWRITE_OPERATION_TYPES,
  type CreateRewriteRuleRequest,
  type RewriteOperation,
  type RewriteRule,
} from '@/api/types'

interface FormState {
  name: string
  direction: string
  conditionMode: 'builder' | 'expression'
  combinator: ExpressionCombinator
  conditions: ExpressionCondition[]
  expression: string
  operations: RewriteOperation[]
  priority: number
  enabled: boolean
}

const emptyCondition = (): ExpressionCondition => ({
  field: EXPRESSION_FIELDS[0].value,
  operator: 'eq',
  value: '',
})

const emptyForm = (): FormState => ({
  name: '',
  direction: 'request',
  conditionMode: 'builder',
  combinator: 'and',
  conditions: [emptyCondition()],
  expression: '',
  operations: [{ type: 'set_header', name: '', value: '' }],
  priority: 100,
  enabled: true,
})

function formFromRule(rule: RewriteRule): FormState {
  const parsed = parseExpression(rule.condition_expr)
  return {
    name: rule.name,
    direction: rule.direction,
    conditionMode: parsed ? 'builder' : rule.condition_expr ? 'expression' : 'builder',
    combinator: parsed?.combinator ?? 'and',
    conditions: parsed?.conditions?.length ? parsed.conditions : [emptyCondition()],
    expression: rule.condition_expr,
    operations: rule.operations.length ? rule.operations : [{ type: 'set_header', name: '', value: '' }],
    priority: rule.priority,
    enabled: rule.enabled,
  }
}

/** Fields each operation type expects, to render the right inputs. */
function operationFields(type: string): { name?: string; value?: string } {
  switch (type) {
    case 'set_header':
    case 'add_header':
      return { name: 'headerName', value: 'headerValue' }
    case 'remove_header':
      return { name: 'headerName' }
    case 'set_path':
      return { value: 'pathValue' }
    case 'regex_replace_path':
      return { name: 'patternValue', value: 'replacementValue' }
    case 'set_query_param':
      return { name: 'paramName', value: 'paramValue' }
    case 'remove_query_param':
      return { name: 'paramName' }
    case 'replace_body':
      return { name: 'searchValue', value: 'replacementValue' }
    default:
      return { name: 'headerName', value: 'headerValue' }
  }
}

export function RewritePage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  // 响应体替换策略挂在站点记录上（`sites.response_replace`），这里与规则列表
  // 一起读取 —— 同一页展示两类"改写"，站点详情页则不再重复拉取。
  const siteQuery = useSiteDetail(siteId)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<RewriteRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm())
  const [error, setError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<RewriteRule | null>(null)

  const rulesQuery = useQuery({
    queryKey: rewriteKeys.list(siteId),
    queryFn: () => rewriteApi.list(siteId),
    enabled: Boolean(siteId),
    select: (page) => page.items,
  })

  const rules = useMemo(
    () =>
      [...(rulesQuery.data ?? [])].sort(
        (a, b) => a.priority - b.priority || a.name.localeCompare(b.name),
      ),
    [rulesQuery.data],
  )

  // Re-seed the dialog form every time it opens (render-phase reset), so the
  // first paint already shows the right rule instead of the previous one.
  const seedKey = dialogOpen ? (editing?.id ?? 'new') : ''
  const [lastSeedKey, setLastSeedKey] = useState<string | null>(null)
  if (seedKey !== lastSeedKey) {
    setLastSeedKey(seedKey)
    if (dialogOpen) {
      setError(null)
      setForm(editing ? formFromRule(editing) : emptyForm())
    }
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: rewriteKeys.all(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: CreateRewriteRuleRequest) =>
      editing
        ? rewriteApi.update(siteId, editing.id, payload)
        : rewriteApi.create(siteId, payload),
    onSuccess: (rule) => {
      toast.success(
        editing ? t('pages.rewrite.ruleUpdated') : t('pages.rewrite.ruleCreated'),
        rule.name,
      )
      closeDialog()
      invalidate()
    },
    onError: (e) => setError(e instanceof Error ? e.message : String(e)),
  })

  const toggle = useMutation({
    mutationFn: ({ rule, enabled }: { rule: RewriteRule; enabled: boolean }) =>
      rewriteApi.toggleEnabled(siteId, rule.id, enabled),
    onSuccess: () => invalidate(),
  })

  const remove = useMutation({
    mutationFn: (id: string) => rewriteApi.delete(siteId, id),
    onSuccess: (_d, id) => {
      toast.success(t('pages.rewrite.ruleDeleted'), rules.find((r) => r.id === id)?.name)
      setPendingDelete(null)
      invalidate()
    },
  })

  const move = useMutation({
    mutationFn: ({ index, dir }: { index: number; dir: -1 | 1 }) => {
      const ids = rules.map((r) => r.id)
      const target = index + dir
      if (target < 0 || target >= ids.length) return Promise.resolve([] as RewriteRule[])
      ;[ids[index], ids[target]] = [ids[target], ids[index]]
      return rewriteApi.reorder(siteId, ids)
    },
    onSuccess: () => invalidate(),
  })

  const closeDialog = () => {
    setDialogOpen(false)
    setEditing(null)
    setForm(emptyForm())
    setError(null)
  }

  const submit = () => {
    setError(null)
    const name = form.name.trim()
    if (!name) {
      setError(t('pages.rewrite.nameRequired'))
      return
    }
    const condition =
      form.conditionMode === 'builder'
        ? buildExpression(form.conditions, form.combinator)
        : form.expression.trim()
    const operations = form.operations.filter(
      (o) => o.type && (o.name?.trim() || o.value?.trim() || o.type === 'remove_header' || o.type === 'remove_query_param'),
    )
    if (operations.length === 0) {
      setError(t('pages.rewrite.operationsRequired'))
      return
    }
    save.mutate({
      name,
      direction: form.direction,
      condition_expr: condition,
      operations: operations.map((o) => ({
        type: o.type,
        name: o.name?.trim() || undefined,
        value: o.value ?? undefined,
      })),
      priority: Number.isFinite(form.priority) ? form.priority : 0,
      enabled: form.enabled,
    })
  }

  const setCondition = (index: number, part: Partial<ExpressionCondition>) =>
    setForm((f) => ({
      ...f,
      conditions: f.conditions.map((c, i) => (i === index ? { ...c, ...part } : c)),
    }))

  const setOperation = (index: number, part: Partial<RewriteOperation>) =>
    setForm((f) => ({
      ...f,
      operations: f.operations.map((o, i) => (i === index ? { ...o, ...part } : o)),
    }))

  const moveOperation = (index: number, dir: -1 | 1) =>
    setForm((f) => {
      const target = index + dir
      if (target < 0 || target >= f.operations.length) return f
      const ops = [...f.operations]
      ;[ops[index], ops[target]] = [ops[target], ops[index]]
      return { ...f, operations: ops }
    })

  const columns: Column<RewriteRule>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
          <p className="pw-mono truncate text-xs text-fg-subtle">
            {r.condition_expr || t('pages.rewrite.always')}
          </p>
        </div>
      ),
    },
    {
      key: 'direction',
      header: t('pages.rewrite.direction'),
      accessor: (r) => r.direction,
      width: '1%',
      cell: (r) => (
        <Badge tone={r.direction === 'request' ? 'info' : 'brand'} size="sm">
          {t(`pages.rewrite.dir.${r.direction}`, r.direction)}
        </Badge>
      ),
    },
    {
      key: 'operations',
      header: t('pages.rewrite.operations'),
      accessor: (r) => r.operations.length,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-subtle">{r.operations.length}</span>
      ),
    },
    {
      key: 'priority',
      header: t('common.priority'),
      accessor: (r) => r.priority,
      sortable: true,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="pw-mono tabular-nums text-xs text-fg-subtle">{r.priority}</span>
      ),
    },
    {
      key: 'enabled',
      header: t('common.enabled'),
      accessor: (r) => (r.enabled ? 1 : 0),
      width: '1%',
      cell: (r) => (
        <Switch
          size="sm"
          checked={r.enabled}
          disabled={!canWrite || toggle.isPending}
          aria-label={`${t('common.enabled')}: ${r.name}`}
          onCheckedChange={(enabled) => toggle.mutate({ rule: r, enabled })}
        />
      ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (r, index) => (
        <div className="flex items-center justify-end gap-0.5">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('pages.rewrite.moveUp')}
            disabled={!canWrite || move.isPending || index === 0}
            onClick={() => move.mutate({ index, dir: -1 })}
            icon={<ArrowUp weight="bold" className="h-3.5 w-3.5" />}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('pages.rewrite.moveDown')}
            disabled={!canWrite || move.isPending || index === rules.length - 1}
            onClick={() => move.mutate({ index, dir: 1 })}
            icon={<ArrowDown weight="bold" className="h-3.5 w-3.5" />}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => {
              setEditing(r)
              setDialogOpen(true)
            }}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(r)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.rewrite.title')}
        description={t('pages.rewrite.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={rulesQuery.isFetching}
              onClick={() => rulesQuery.refetch()}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => {
                  setEditing(null)
                  setDialogOpen(true)
                }}
              >
                {t('pages.rewrite.addRule')}
              </Button>
            )}
          </div>
        }
      />

      {rulesQuery.isError && !rulesQuery.data ? (
        <ErrorState
          error={rulesQuery.error}
          onRetry={() => rulesQuery.refetch()}
          retrying={rulesQuery.isFetching}
        />
      ) : (
        <Card>
          <CardHeader
            title={t('pages.rewrite.rulesTitle')}
            description={t('pages.rewrite.reorderHint')}
          />
          <CardBody className="p-0">
            {rulesQuery.isPending ? (
              <SkeletonRows rows={4} columns={6} />
            ) : rules.length === 0 ? (
              <EmptyState
                className="border-0 py-12"
                icon={<Sliders weight="duotone" className="h-8 w-8" />}
                title={t('pages.rewrite.empty')}
                description={t('pages.rewrite.emptyDescription')}
                action={
                  canWrite ? (
                    <Button
                      variant="primary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={() => {
                        setEditing(null)
                        setDialogOpen(true)
                      }}
                    >
                      {t('pages.rewrite.addRule')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table columns={columns} data={rules} rowKey={(r) => r.id} dense />
            )}
          </CardBody>
        </Card>
      )}

      {/* 响应体替换（`sites.response_replace`）：与规则列表同属"改写"，
          原来在站点基础设置里，2026-10-23 移到本页。

          `key` 带上服务端已保存的策略：卡片把表单存进本地 state，保存后
          invalidate 会换回新的 `site` 对象；不重挂载的话本地 state 仍是提交前的
          值，服务端一旦做过规范化（例如把空 path 补成 `^/.*`）就会永久显示为
          "有未保存修改"。策略一变就重挂载，本地状态回到服务端的真值。 */}
      {siteQuery.data && (
        <div className="mt-6">
          <ResponseReplaceCard
            key={`${siteQuery.data.site.id}:${JSON.stringify(siteQuery.data.site.response_replace ?? null)}`}
            site={siteQuery.data.site}
          />
        </div>
      )}

      {siteQuery.isError && (
        <div className="mt-6">
          <ErrorState
            variant="inline"
            error={siteQuery.error}
            onRetry={() => void siteQuery.refetch()}
            retrying={siteQuery.isFetching}
          />
        </div>
      )}

      <Dialog
        open={dialogOpen}
        onClose={save.isPending ? () => undefined : closeDialog}
        size="lg"
        title={editing ? t('pages.rewrite.editRule') : t('pages.rewrite.addRule')}
        description={t('pages.rewrite.dialogDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={closeDialog} disabled={save.isPending}>
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submit} loading={save.isPending}>
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-5">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              label={t('common.name')}
              value={form.name}
              autoFocus
              placeholder={t('pages.rewrite.namePlaceholder')}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              required
            />
            <Select
              label={t('pages.rewrite.direction')}
              value={form.direction}
              options={REWRITE_DIRECTIONS.map((d) => ({
                value: d,
                label: t(`pages.rewrite.dir.${d}`, d),
              }))}
              onChange={(e) => setForm((f) => ({ ...f, direction: e.target.value }))}
            />
          </div>

          {/* Condition */}
          <div>
            <Tabs
              variant="pill"
              className="mb-3"
              value={form.conditionMode}
              onChange={(mode) =>
                setForm((f) => {
                  if (mode === 'expression' && f.conditionMode === 'builder') {
                    return { ...f, conditionMode: 'expression', expression: buildExpression(f.conditions, f.combinator) }
                  }
                  if (mode === 'builder' && f.conditionMode === 'expression') {
                    const parsed = parseExpression(f.expression)
                    return {
                      ...f,
                      conditionMode: 'builder',
                      combinator: parsed?.combinator ?? 'and',
                      conditions: parsed?.conditions?.length ? parsed.conditions : [emptyCondition()],
                    }
                  }
                  return { ...f, conditionMode: mode as FormState['conditionMode'] }
                })
              }
              items={[
                { value: 'builder', label: t('pages.rewrite.conditionBuilder') },
                { value: 'expression', label: t('pages.rewrite.expressionEditor') },
              ]}
            />
            {form.conditionMode === 'builder' ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-fg-subtle">{t('pages.rewrite.matchWhen')}</span>
                  <Select
                    className="h-7 w-24 text-xs"
                    value={form.combinator}
                    options={[
                      { value: 'and', label: t('pages.rewrite.all') },
                      { value: 'or', label: t('pages.rewrite.any') },
                    ]}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, combinator: e.target.value as ExpressionCombinator }))
                    }
                  />
                </div>
                {form.conditions.map((c, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <Select
                      className="h-9 w-40 text-xs"
                      value={c.field}
                      options={EXPRESSION_FIELDS.map((f) => ({
                        value: f.value,
                        label: t(`pages.waf.fields.${f.labelKey}`, f.value),
                      }))}
                      onChange={(e) => setCondition(i, { field: e.target.value })}
                    />
                    <Select
                      className="h-9 w-36 text-xs"
                      value={c.operator}
                      options={EXPRESSION_OPERATORS.map((o) => ({
                        value: o,
                        label: t(`operators.${o}`, o),
                      }))}
                      onChange={(e) =>
                        setCondition(i, { operator: e.target.value as ExpressionOperator })
                      }
                    />
                    <Input
                      className="h-9 flex-1 text-xs"
                      value={c.value}
                      placeholder={t('common.value')}
                      onChange={(e) => setCondition(i, { value: e.target.value })}
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      className="hover:text-fg-danger"
                      aria-label={t('common.delete')}
                      disabled={form.conditions.length === 1}
                      onClick={() =>
                        setForm((f) => ({
                          ...f,
                          conditions: f.conditions.filter((_, idx) => idx !== i),
                        }))
                      }
                      icon={<X weight="bold" className="h-4 w-4" />}
                    />
                  </div>
                ))}
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-fit"
                  icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                  onClick={() =>
                    setForm((f) => ({ ...f, conditions: [...f.conditions, emptyCondition()] }))
                  }
                >
                  {t('pages.rewrite.addCondition')}
                </Button>
              </div>
            ) : (
              <Textarea
                mono
                rows={3}
                value={form.expression}
                placeholder='http.request.uri.path starts_with "/api"'
                onChange={(e) => setForm((f) => ({ ...f, expression: e.target.value }))}
              />
            )}
          </div>

          {/* Operations */}
          <div>
            <p className="mb-2 text-[13px] font-medium text-fg">{t('pages.rewrite.operations')}</p>
            <div className="flex flex-col gap-2">
              {form.operations.map((op, i) => {
                const fields = operationFields(op.type)
                return (
                  <div
                    key={i}
                    className="rounded-md border border-line bg-recessed/50 p-2.5"
                  >
                    <div className="flex items-center gap-2">
                      <Select
                        className="h-8 flex-1 text-xs"
                        value={op.type}
                        options={REWRITE_OPERATION_TYPES.map((ty) => ({
                          value: ty,
                          label: t(`operations.${ty}`, ty),
                        }))}
                        onChange={(e) => setOperation(i, { type: e.target.value })}
                      />
                      <div className="flex items-center">
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label={t('pages.rewrite.moveUp')}
                          disabled={i === 0}
                          onClick={() => moveOperation(i, -1)}
                          icon={<ArrowUp weight="bold" className="h-3.5 w-3.5" />}
                        />
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label={t('pages.rewrite.moveDown')}
                          disabled={i === form.operations.length - 1}
                          onClick={() => moveOperation(i, 1)}
                          icon={<ArrowDown weight="bold" className="h-3.5 w-3.5" />}
                        />
                        <Button
                          size="icon"
                          variant="ghost"
                          className="hover:text-fg-danger"
                          aria-label={t('common.delete')}
                          disabled={form.operations.length === 1}
                          onClick={() =>
                            setForm((f) => ({
                              ...f,
                              operations: f.operations.filter((_, idx) => idx !== i),
                            }))
                          }
                          icon={<Trash weight="duotone" className="h-4 w-4" />}
                        />
                      </div>
                    </div>
                    <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                      {fields.name && (
                        <Input
                          className="h-8 text-xs"
                          value={op.name ?? ''}
                          placeholder={t(`pages.rewrite.placeholders.${fields.name}`)}
                          onChange={(e) => setOperation(i, { name: e.target.value })}
                        />
                      )}
                      {fields.value && (
                        <Input
                          className="h-8 text-xs"
                          value={op.value ?? ''}
                          placeholder={t(`pages.rewrite.placeholders.${fields.value}`)}
                          onChange={(e) => setOperation(i, { value: e.target.value })}
                        />
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="mt-2 w-fit"
              icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
              onClick={() =>
                setForm((f) => ({
                  ...f,
                  operations: [...f.operations, { type: 'set_header', name: '', value: '' }],
                }))
              }
            >
              {t('pages.rewrite.addOperation')}
            </Button>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              type="number"
              label={t('common.priority')}
              value={form.priority}
              min={0}
              hint={t('pages.rewrite.priorityHint')}
              onChange={(e) => setForm((f) => ({ ...f, priority: Number(e.target.value) }))}
            />
            <div className="flex items-end pb-1">
              <Switch
                checked={form.enabled}
                onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
                label={t('common.enabled')}
              />
            </div>
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {error}
            </p>
          )}
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.rewrite.deleteTitle')}
        description={t('pages.rewrite.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDelete.name}</p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

export default RewritePage
