import { POST_PROCESSOR_ANALYZERS } from './constants'

export function isPostProcessorResult(analyzerName: string): boolean {
  return (POST_PROCESSOR_ANALYZERS as readonly string[]).includes(analyzerName)
}
