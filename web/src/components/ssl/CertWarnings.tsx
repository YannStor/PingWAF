import { useTranslation } from 'react-i18next'
import { Warning } from '@phosphor-icons/react'
import { Tooltip } from '@/components/ui/Tooltip'

/**
 * Non-fatal server notices for a certificate row (e.g. a SAN that is not
 * served by the site). Saving is never rejected; the badge is advisory only.
 */
export function CertWarningsBadge({ warnings }: { warnings?: string[] }) {
  const { t } = useTranslation()
  if (!warnings || warnings.length === 0) return null
  return (
    <Tooltip
      content={
        <span className="flex flex-col items-start gap-0.5">
          {warnings.map((warning) => (
            <span key={warning}>{warning}</span>
          ))}
        </span>
      }
    >
      <span
        role="img"
        aria-label={
          warnings.length > 1
            ? t('pages.ssl.certDomainWarnings', { count: warnings.length })
            : t('pages.ssl.certDomainWarning')
        }
        className="inline-flex h-5 w-5 shrink-0 cursor-help items-center justify-center rounded-full bg-warning/15 text-fg-warning"
      >
        <Warning weight="fill" className="h-3.5 w-3.5" />
      </span>
    </Tooltip>
  )
}
