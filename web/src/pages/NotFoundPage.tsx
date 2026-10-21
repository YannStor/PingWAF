import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'

/**
 * Full 404 page. Extracted from the inline copy in `router/index.tsx` so the
 * page has a real `<h1>` (L1-002): accessibility scanners read the heading,
 * and the empty-state title alone was rendering as a `<p>`.
 *
 * ⚠️ `router/index.tsx` still holds the inline component; switch its
 * `{ path: '*', element: <NotFoundPage /> }` import to this file (one-line
 * change, out of this change's allowed file set).
 */
export function NotFoundPage() {
  const { t } = useTranslation()
  return (
    <div className="animate-slide-up">
      <h1 className="text-2xl font-semibold text-fg-strong">
        {t('notFound.title', t('pages.notFound.title'))}
      </h1>
      <EmptyState
        title={<span className="sr-only">{t('pages.notFound.title')}</span>}
        description={t('pages.notFound.description')}
        action={
          <Link to="/dashboard">
            <Button variant="primary">{t('pages.notFound.backToDashboard')}</Button>
          </Link>
        }
      />
    </div>
  )
}

export default NotFoundPage
