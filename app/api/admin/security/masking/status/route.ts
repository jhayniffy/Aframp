import { NextResponse } from 'next/server'
import { getRules } from '@/lib/security/masking-config'
import { runMaskingEffectivenessTest, getMaskingCounters, OutputChannel } from '@/lib/security/masking'

const ALL_CHANNELS: OutputChannel[] = ['log_field', 'log_message', 'api_error', 'api_response', 'tracing', 'metrics', 'db_query']

export function GET() {
  const rules = getRules()
  const results = runMaskingEffectivenessTest(rules, ALL_CHANNELS)
  const allPassed = results.every((r) => r.passed)

  return NextResponse.json({
    overall: allPassed ? 'healthy' : 'degraded',
    channels: results,
    counters: getMaskingCounters(),
  })
}
