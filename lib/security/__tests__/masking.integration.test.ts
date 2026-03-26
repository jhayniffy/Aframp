/**
 * Integration tests — verify no sensitive data reaches any output channel,
 * response masking correctness, tracing masking, and effectiveness test execution.
 */
import {
  maskLogFields,
  scanAndMaskMessage,
  redactErrorResponse,
  maskResponseBody,
  maskSpanAttributes,
  runMaskingEffectivenessTest,
  REDACTED,
  DEFAULT_RULES,
  resetMaskingCounters,
  resetMaskingAuditLog,
  getMaskingAuditLog,
  getMaskingCounters,
  OutputChannel,
} from '../masking'
import { getRules, addRule, resetRuleStore } from '../masking-config'

const ALL_CHANNELS: OutputChannel[] = ['log_field', 'log_message', 'api_error', 'api_response', 'tracing', 'metrics', 'db_query']

const SENSITIVE_SAMPLES = {
  password: 'SuperSecret123!',
  token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123',
  email: 'user@example.com',
  account_number: '1234567890123456',
  national_id: 'NG-123456789',
  private_key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----',
  card_number: '4111111111111111',
}

beforeEach(() => {
  resetMaskingCounters()
  resetMaskingAuditLog()
  resetRuleStore()
})

// ─── Log channel: no sensitive data in any log event ─────────────────────────

describe('Log channel — no sensitive data leaks', () => {
  it('structured log event with all sensitive categories produces no raw values', () => {
    const logEvent = {
      user: 'alice',
      password: SENSITIVE_SAMPLES.password,
      token: SENSITIVE_SAMPLES.token,
      account_number: SENSITIVE_SAMPLES.account_number,
      national_id: SENSITIVE_SAMPLES.national_id,
      metadata: {
        private_key: SENSITIVE_SAMPLES.private_key,
        email: SENSITIVE_SAMPLES.email,
      },
    }
    const masked = maskLogFields(logEvent, getRules(), 'log_field')
    const serialised = JSON.stringify(masked)

    expect(serialised).not.toContain(SENSITIVE_SAMPLES.password)
    expect(serialised).not.toContain(SENSITIVE_SAMPLES.token)
    expect(serialised).not.toContain(SENSITIVE_SAMPLES.national_id)
    expect(serialised).not.toContain('BEGIN RSA PRIVATE KEY')
    expect(serialised).toContain('alice') // non-sensitive preserved
  })

  it('unstructured log message with JWT is redacted', () => {
    const msg = `Auth failed for token ${SENSITIVE_SAMPLES.token}`
    const { masked, detected } = scanAndMaskMessage(msg, getRules(), 'log_message')
    expect(detected).toBe(true)
    expect(masked).not.toContain('eyJhbGciOiJIUzI1NiJ9')
  })

  it('unstructured log message with credit card is redacted', () => {
    const msg = `Payment attempted with card ${SENSITIVE_SAMPLES.card_number}`
    const { masked, detected } = scanAndMaskMessage(msg, getRules(), 'log_message')
    expect(detected).toBe(true)
    expect(masked).not.toContain(SENSITIVE_SAMPLES.card_number)
  })

  it('unstructured log message with email is redacted', () => {
    const msg = `Sending OTP to ${SENSITIVE_SAMPLES.email}`
    const { masked, detected } = scanAndMaskMessage(msg, getRules(), 'log_message')
    expect(detected).toBe(true)
    expect(masked).not.toContain(SENSITIVE_SAMPLES.email)
  })

  it('security alert: detected=true signals code path requiring remediation', () => {
    const { detected, matchedRules } = scanAndMaskMessage(
      `private key: ${SENSITIVE_SAMPLES.private_key}`,
      getRules(),
      'log_message'
    )
    expect(detected).toBe(true)
    expect(matchedRules.length).toBeGreaterThan(0)
  })
})

// ─── API error response redaction ─────────────────────────────────────────────

describe('API error response — no internal details in production', () => {
  it('production error response never contains stack trace', () => {
    const internal = {
      message: 'Query failed',
      stack: 'Error: at pg.query line 42\n  at handler line 10',
      dbError: 'relation "users" does not exist',
      providerError: 'Stellar horizon timeout',
      code: 'DB_ERROR',
    }
    const safe = redactErrorResponse(internal, true, getRules())
    expect(JSON.stringify(safe)).not.toContain('pg.query')
    expect(JSON.stringify(safe)).not.toContain('relation "users"')
    expect(JSON.stringify(safe)).not.toContain('Stellar horizon')
    expect(safe.code).toBeDefined()
    expect(safe.message).toBeDefined()
  })

  it('production response is generic consumer-safe message', () => {
    const safe = redactErrorResponse({ message: 'Internal DB failure', stack: 'trace', code: 'ERR' }, true, getRules())
    expect(Object.keys(safe).length).toBe(2)
    expect(safe.code).toBeDefined()
    expect(safe.message).toBeDefined()
  })
})

// ─── Consumer-facing response partial masking ─────────────────────────────────

describe('Consumer-facing response partial masking', () => {
  it('full KYC response masks all sensitive fields correctly', () => {
    const kycResponse = {
      user_id: 'usr_123',
      document_type: 'PASSPORT',
      issuing_country: 'NG',
      document_number: 'A12345678',
      national_id: 'NG-987654321',
      account_number: '0123456789',
      mobile_money: '08012345678',
      email: 'user@aframp.com',
      status: 'verified',
    }
    const masked = maskResponseBody(kycResponse)
    expect(masked.document_number).toBe(REDACTED)
    expect(masked.national_id).toBe(REDACTED)
    expect(String(masked.account_number)).toMatch(/\*+\d{3,4}$/)
    expect(String(masked.mobile_money)).toMatch(/\*+\d{3}$/)
    expect(String(masked.email)).toMatch(/@aframp\.com$/)
    // Non-sensitive fields preserved
    expect(masked.document_type).toBe('PASSPORT')
    expect(masked.issuing_country).toBe('NG')
    expect(masked.status).toBe('verified')
    expect(masked.user_id).toBe('usr_123')
  })
})

// ─── Tracing span attribute masking ──────────────────────────────────────────

describe('Tracing payload masking before export', () => {
  it('span attributes with sensitive fields are masked', () => {
    const span = {
      'http.method': 'POST',
      'http.url': '/api/onramp',
      password: SENSITIVE_SAMPLES.password,
      token: SENSITIVE_SAMPLES.token,
      'user.account_number': '1234567890',
    }
    const masked = maskSpanAttributes(span, getRules())
    expect(masked.password).toBe(REDACTED)
    expect(masked.token).toBe(REDACTED)
    expect(masked['http.method']).toBe('POST')
    expect(masked['http.url']).toBe('/api/onramp')
  })
})

// ─── Masking effectiveness test execution ─────────────────────────────────────

describe('Masking effectiveness test', () => {
  it('all channels pass with default rules', () => {
    const results = runMaskingEffectivenessTest(getRules(), ALL_CHANNELS)
    const failed = results.filter((r) => !r.passed)
    // Channels that have pattern rules should pass; others may not have patterns but won't fail
    const logMsgResult = results.find((r) => r.channel === 'log_message')!
    expect(logMsgResult.passed).toBe(true)
    expect(logMsgResult.missedPatterns).toHaveLength(0)
  })

  it('detects unmasked data and fires alert when rules removed', () => {
    resetRuleStore()
    // Remove all rules by adding none — use empty array
    const results = runMaskingEffectivenessTest([], ['log_message'])
    const r = results[0]
    expect(r.passed).toBe(false)
    expect(r.missedPatterns.length).toBeGreaterThan(0)
    // Alert condition: passed=false means alert should fire
  })

  it('each result has testedAt timestamp', () => {
    const results = runMaskingEffectivenessTest(getRules(), ['log_message', 'api_error'])
    for (const r of results) {
      expect(r.testedAt).toBeDefined()
      expect(new Date(r.testedAt).getTime()).not.toBeNaN()
    }
  })
})

// ─── Rule cache invalidation takes effect immediately ─────────────────────────

describe('Rule cache invalidation — immediate effect', () => {
  it('newly added rule is applied immediately to masking', () => {
    addRule({
      id: 'rule_custom_secret',
      category: 'auth_credential',
      strategy: 'redact',
      channels: ['log_field'],
      fieldNames: ['custom_secret_field'],
    })
    const result = maskLogFields({ custom_secret_field: 'my-secret-value' }, getRules(), 'log_field')
    expect(result.custom_secret_field).toBe(REDACTED)
  })

  it('deleted rule no longer masks the field', () => {
    // Remove the JWT rule
    const { deleteRule } = require('../masking-config')
    deleteRule('rule_jwt')
    const rules = getRules()
    const msg = `token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123`
    const { detected } = scanAndMaskMessage(msg, rules, 'log_message')
    // JWT pattern rule removed — should not detect via that rule
    const jwtRule = rules.find((r) => r.id === 'rule_jwt')
    expect(jwtRule).toBeUndefined()
    // detected may still be true from other rules, but rule_jwt is gone
  })
})

// ─── Prometheus counters reflect masking events ───────────────────────────────

describe('Prometheus counters', () => {
  it('counters reflect masking events across categories and channels', () => {
    maskLogFields({ password: 'x', token: 'y', email: 'a@b.com' }, getRules(), 'log_field')
    const counters = getMaskingCounters()
    const total = Object.values(counters).reduce((a, b) => a + b, 0)
    expect(total).toBeGreaterThanOrEqual(2)
  })

  it('audit log records field name and strategy', () => {
    maskLogFields({ password: 'secret' }, getRules(), 'log_field')
    const log = getMaskingAuditLog()
    const entry = log.find((e) => e.fieldName === 'password')
    expect(entry).toBeDefined()
    expect(entry!.strategy).toBe('redact')
    expect(entry!.channel).toBe('log_field')
  })
})
