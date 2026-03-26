import { NextRequest, NextResponse } from 'next/server'
import {
  bugBountyReports, BugBountyReport,
  detectDuplicateBugBounty, uid,
} from '@/lib/security/pentest'

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url)
  const status = searchParams.get('status')
  let list = Array.from(bugBountyReports.values())
  if (status) list = list.filter((r) => r.triage_status === status)
  return NextResponse.json(list)
}

export async function POST(req: NextRequest) {
  const body = await req.json()
  const { title, affected_component, description, proof_of_concept, reporter_contact } = body
  if (!title || !affected_component || !description || !proof_of_concept || !reporter_contact) {
    return NextResponse.json({ error: 'Missing required fields' }, { status: 400 })
  }

  const now = new Date()
  const existing = Array.from(bugBountyReports.values())
  const duplicate = detectDuplicateBugBounty({ title, affected_component }, existing)

  const report: BugBountyReport = {
    id: uid(),
    title,
    severity: null,
    affected_component,
    description,
    proof_of_concept,
    reporter_contact,
    triage_status: duplicate ? 'duplicate' : 'pending',
    duplicate_of: duplicate?.id,
    acknowledged_at: now.toISOString(),
    // triage within 72h, remediation timeline within 7 days
    triage_deadline: new Date(now.getTime() + 72 * 3600000).toISOString(),
    remediation_timeline_deadline: new Date(now.getTime() + 7 * 24 * 3600000).toISOString(),
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  }
  bugBountyReports.set(report.id, report)

  console.log(JSON.stringify({
    event: 'bug_bounty_report_submitted',
    report_id: report.id,
    duplicate: !!duplicate,
    duplicate_of: duplicate?.id ?? null,
    timestamp: report.created_at,
  }))

  return NextResponse.json(report, { status: 201 })
}
