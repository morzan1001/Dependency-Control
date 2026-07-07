import { Navigate } from 'react-router-dom'

/**
 * The standalone dependency search page has been superseded by the
 * Analytics "Dependencies" tab (CrossProjectSearch). This route is kept
 * only so the /search/dependencies deep link keeps working — it now
 * redirects to /analytics rather than duplicating the search UI.
 */
export default function SearchPage() {
  return <Navigate to="/analytics" replace />
}
