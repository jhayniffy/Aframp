import { NextRequest, NextResponse } from 'next/server'
import { getRuleById, updateRule, deleteRule } from '@/lib/security/masking-config'

export function GET(_req: NextRequest, { params }: { params: { rule_id: string } }) {
  const rule = getRuleById(params.rule_id)
  if (!rule) return NextResponse.json({ error: 'Rule not found' }, { status: 404 })
  return NextResponse.json({ rule })
}

export async function PATCH(req: NextRequest, { params }: { params: { rule_id: string } }) {
  const patch = await req.json()
  const updated = updateRule(params.rule_id, patch)
  if (!updated) return NextResponse.json({ error: 'Rule not found' }, { status: 404 })
  return NextResponse.json({ rule: updated })
}

export async function DELETE(_req: NextRequest, { params }: { params: { rule_id: string } }) {
  const existed = deleteRule(params.rule_id)
  if (!existed) return NextResponse.json({ error: 'Rule not found' }, { status: 404 })
  return NextResponse.json({ deleted: true })
}
