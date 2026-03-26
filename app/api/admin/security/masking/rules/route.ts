import { NextRequest, NextResponse } from 'next/server'
import { getRules, addRule } from '@/lib/security/masking-config'
import { MaskingRule } from '@/lib/security/masking'

export function GET() {
  return NextResponse.json({ rules: getRules() })
}

export async function POST(req: NextRequest) {
  const body = await req.json() as Partial<MaskingRule>
  if (!body.id || !body.category || !body.strategy || !body.channels?.length) {
    return NextResponse.json({ error: 'id, category, strategy, and channels are required' }, { status: 400 })
  }
  const rule = addRule({
    id: body.id,
    category: body.category,
    strategy: body.strategy,
    channels: body.channels,
    fieldNames: body.fieldNames,
    patternSource: body.patternSource,
  })
  return NextResponse.json({ rule }, { status: 201 })
}
