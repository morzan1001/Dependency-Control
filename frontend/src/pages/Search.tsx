import { Navigate } from 'react-router-dom'

// Redirects the /search/dependencies deep link to the Analytics Dependencies tab.
export default function SearchPage() {
  return <Navigate to="/analytics" replace />
}
