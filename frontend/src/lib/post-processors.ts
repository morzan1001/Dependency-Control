export function isPostProcessorResult(analyzerName: string): boolean {
  return analyzerName === 'epss_kev' || analyzerName === 'reachability'
}
