import { NextRequest, NextResponse } from 'next/server'
import { bugBountyReports } from '@/lib/security/pentest'

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ report_id: string }> }
) {
  const { report_id } = await params
  const report = bugBountyReports.get(report_id)
  if (!report) return NextResponse.json({ error: 'Report not found' }, { status: 404 })

  const body = await req.json()
  const { triage_status, severity, reward_decision } = body

  const updated = {
    ...report,
    ...(triage_status && { triage_status }),
    ...(severity !== undefined && { severity }),
    ...(reward_decision !== undefined && { reward_decision }),
    updated_at: new Date().toISOString(),
  }
  bugBountyReports.set(report_id, updated)

  // Alert on critical bug bounty finding
  if (severity === 'critical') {
    console.log(JSON.stringify({
      event: 'critical_finding_submitted',
      source: 'bug_bounty',
      report_id,
      title: updated.title,
      timestamp: updated.updated_at,
    }))
  }

  console.log(JSON.stringify({
    event: 'bug_bounty_report_updated',
    report_id,
    triage_status: updated.triage_status,
    severity: updated.severity,
    timestamp: updated.updated_at,
  }))

  return NextResponse.json(updated)
}
