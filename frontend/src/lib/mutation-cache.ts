import { MutationCache } from '@tanstack/react-query'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/utils'

declare module '@tanstack/react-query' {
  interface Register {
    mutationMeta: { errorTitle?: string }
  }
}

export const createMutationCache = () =>
  new MutationCache({
    onError: (error, _variables, _onMutateResult, mutation) => {
      const title = mutation.meta?.errorTitle
      if (title) toast.error(title, { description: getErrorMessage(error) })
    },
  })
