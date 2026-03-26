import {
  maskLogFields,
  scanAndMaskMessage,
  redactErrorResponse,
  maskResponseBody,
  maskSpanAttributes,
  applyPartialMask,
  applyStrategy,
  applyTokenise,
  applyFormatPreserve,
  runMaskingEffectivenessTest,
  validateDebugMode,
  REDACTED,
  DEFAULT_RULES,
  getMaskingCounters,
  resetMaskingCounters,
  resetMaskingAuditLog,
  getMaskingAuditLog,
  DEFAULT_RESPONSE_POLICY,
} from '../masking'
import {
  getRules,
  addRule,
  updateRule,
  deleteRule,
  resetRuleStore,
  getCacheVersion,
} from '../masking-config'

beforeEach(() => {
  resetMaskingCounters()
  resetMaskingAuditLog()
  resetRuleStore()
})

// ─── Strategy unit tests ──────────────────────────────────────────────────────

describe('applyPartialMask', () => {
  it('bank_account shows last 4 digits', () => {
    expect(applyPartialMask('1234567890', 'bank_account')).toBe('****7890')
  })

  it('mobile_money shows last 3 digits', () => {
    expect(applyPartialMask('08012345678', 'mobile_money')).toBe('****678')
  })

  it('email masks local part', () => {
    const result = applyPartialMask('user@example.com', 'email')
    expect(result).toMatch(/^u\*+@example\.com$/)
  })

  it('default masks all but last 4', () => {
    expect(applyPartialMask('ABCDEFGH')).toBe('****EFGH')
  })

  it('short value returns REDACTED', () => {
    expect(applyPartialMask('123')).toBe(REDACTED)
  })
})

describe('applyFormatPreserve', () => {
  it('replaces alphanumeric with asterisks preserving length', () => {
    const result = applyFormatPreserve('ABC-123')
    expect(result).toBe('***-***')
    expect(result.length).toBe('ABC-123'.length)
  })
})

describe('applyTokenise', () => {
  it('produces deterministic token for same input', () => {
    expect(applyTokenise('secret')).toBe(applyTokenise('secret'))
  })

  it('produces different tokens for different inputs', () => {
    expect(applyTokenise('secret1')).not.toBe(applyTokenise('secret2'))
  })

  it('token starts with tok_', () => {
    expect(applyTokenise('any')).toMatch(/^tok_/)
  })
})

describe('applyStrategy', () => {
  it('redact returns REDACTED', () => {
    expect(applyStrategy('value', 'redact')).toBe(REDACTED)
  })

  it('partial on financial_account uses bank_account mask for long numbers (>11 digits)', () => {
    // 13-digit number → bank_account mask (last 4)
    expect(applyStrategy('1234567890123', 'partial', 'financial_account')).toBe('****0123')
  })

  it('partial on financial_account uses mobile_money mask for short numbers (<=11 digits)', () => {
    // 11-digit number → mobile_money mask (last 3)
    expect(applyStrategy('08012345678', 'partial', 'financial_account')).toBe('****678')
  })

  it('partial on contact_info uses email mask', () => {
    expect(applyStrategy('a@b.com', 'partial', 'contact_info')).toMatch(/@b\.com$/)
  })
})

// ─── Structured log field masking ─────────────────────────────────────────────

describe('maskLogFields', () => {
  it('masks top-level sensitive field', () => {
    const result = maskLogFields({ password: 'secret123', user: 'alice' }, DEFAULT_RULES)
    expect(result.password).toBe(REDACTED)
    expect(result.user).toBe('alice')
  })

  it('masks nested sensitive field at any depth', () => {
    const input = { level1: { level2: { level3: { token: 'abc' } } } }
    const result = maskLogFields(input, DEFAULT_RULES) as Record<string, unknown>
    const l1 = result.level1 as Record<string, unknown>
    const l2 = l1.level2 as Record<string, unknown>
    const l3 = l2.level3 as Record<string, unknown>
    expect(l3.token).toBe(REDACTED)
  })

  it('is case-insensitive for field names', () => {
    const result = maskLogFields({ PASSWORD: 'secret', Token: 'tok' }, DEFAULT_RULES)
    expect(result.PASSWORD).toBe(REDACTED)
    expect(result.Token).toBe(REDACTED)
  })

  it('records masking event and increments counter', () => {
    maskLogFields({ password: 'x' }, DEFAULT_RULES)
    const log = getMaskingAuditLog()
    expect(log.length).toBeGreaterThan(0)
    expect(log[0].fieldName).toBe('password')
    const counters = getMaskingCounters()
    const key = Object.keys(counters).find((k) => k.includes('auth_credential'))
    expect(key).toBeDefined()
    expect(counters[key!]).toBeGreaterThan(0)
  })

  it('does not mask non-sensitive fields', () => {
    const result = maskLogFields({ amount: '100', currency: 'NGN' }, DEFAULT_RULES)
    expect(result.amount).toBe('100')
    expect(result.currency).toBe('NGN')
  })
})

// ─── Pattern scanner ──────────────────────────────────────────────────────────

describe('scanAndMaskMessage', () => {
  it('detects and masks JWT token in message', () => {
    const msg = 'User token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123'
    const { masked, detected } = scanAndMaskMessage(msg, DEFAULT_RULES)
    expect(detected).toBe(true)
    expect(masked).not.toContain('eyJhbGciOiJIUzI1NiJ9')
    expect(masked).toContain(REDACTED)
  })

  it('detects and masks email address in message', () => {
    const msg = 'User email is test@example.com for account'
    const { masked, detected } = scanAndMaskMessage(msg, DEFAULT_RULES)
    expect(detected).toBe(true)
    expect(masked).not.toContain('test@example.com')
  })

  it('detects and masks credit card number', () => {
    const msg = 'Card used: 4111111111111111 for payment'
    const { masked, detected } = scanAndMaskMessage(msg, DEFAULT_RULES)
    expect(detected).toBe(true)
    expect(masked).not.toContain('4111111111111111')
  })

  it('detects PEM private key block', () => {
    const msg = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----'
    const { masked, detected } = scanAndMaskMessage(msg, DEFAULT_RULES)
    expect(detected).toBe(true)
    expect(masked).not.toContain('BEGIN RSA PRIVATE KEY')
  })

  it('returns detected=false for clean message', () => {
    const { detected } = scanAndMaskMessage('Transaction completed for NGN 5000', DEFAULT_RULES)
    expect(detected).toBe(false)
  })
})

// ─── API error response redaction ─────────────────────────────────────────────

describe('redactErrorResponse', () => {
  it('strips stack trace in production', () => {
    const body = { message: 'DB error', stack: 'Error at line 42', code: 'DB_ERR' }
    const result = redactErrorResponse(body, true, DEFAULT_RULES)
    expect(result.stack).toBeUndefined()
    expect(result.message).toBeDefined()
  })

  it('strips db_error and provider_error in production', () => {
    const body = { message: 'fail', dbError: 'syntax error near SELECT', providerError: 'timeout' }
    const result = redactErrorResponse(body, true, DEFAULT_RULES)
    expect(result.dbError).toBeUndefined()
    expect(result.providerError).toBeUndefined()
  })

  it('production response only contains code and message', () => {
    const body = { message: 'fail', code: 'ERR', extra: 'internal detail', stack: 'trace' }
    const result = redactErrorResponse(body, true, DEFAULT_RULES)
    expect(Object.keys(result)).toEqual(expect.arrayContaining(['code', 'message']))
    expect(result.extra).toBeUndefined()
  })

  it('non-production includes extra context but still strips internal fields', () => {
    const body = { message: 'fail', code: 'ERR', extra: 'context', stack: 'trace' }
    const result = redactErrorResponse(body, false, DEFAULT_RULES)
    expect(result.extra).toBe('context')
    expect(result.stack).toBeUndefined()
  })
})

// ─── Response body partial masking ───────────────────────────────────────────

describe('maskResponseBody', () => {
  it('masks bank account number (>11 digits) showing last 4 digits', () => {
    const result = maskResponseBody({ account_number: '123456789012' }, DEFAULT_RESPONSE_POLICY)
    expect(String(result.account_number)).toMatch(/\*+\d{4}$/)
    expect(String(result.account_number)).not.toContain('123456')
  })

  it('masks short account number (<=11 digits) showing last 3 digits', () => {
    const result = maskResponseBody({ account_number: '1234567890' }, DEFAULT_RESPONSE_POLICY)
    expect(String(result.account_number)).toMatch(/\*+\d{3}$/)
  })

  it('masks mobile money showing last 3 digits', () => {
    const result = maskResponseBody({ mobile_money: '08012345678' }, DEFAULT_RESPONSE_POLICY)
    expect(String(result.mobile_money)).toMatch(/\*+\d{3}$/)
  })

  it('redacts government ID document number', () => {
    const result = maskResponseBody({ document_number: 'A12345678' }, DEFAULT_RESPONSE_POLICY)
    expect(result.document_number).toBe(REDACTED)
  })

  it('redacts national_id', () => {
    const result = maskResponseBody({ national_id: 'NG-123456789' }, DEFAULT_RESPONSE_POLICY)
    expect(result.national_id).toBe(REDACTED)
  })

  it('masks email in response', () => {
    const result = maskResponseBody({ email: 'user@domain.com' }, DEFAULT_RESPONSE_POLICY)
    expect(String(result.email)).toMatch(/@domain\.com$/)
    expect(String(result.email)).not.toContain('user@')
  })

  it('passes through non-sensitive fields unchanged', () => {
    const result = maskResponseBody({ amount: '5000', currency: 'NGN' }, DEFAULT_RESPONSE_POLICY)
    expect(result.amount).toBe('5000')
    expect(result.currency).toBe('NGN')
  })
})

// ─── Tracing span attribute masking ──────────────────────────────────────────

describe('maskSpanAttributes', () => {
  it('masks sensitive span attributes before export', () => {
    const attrs = { 'user.token': 'abc', 'http.method': 'POST', password: 'secret' }
    const result = maskSpanAttributes(attrs, DEFAULT_RULES)
    expect(result.password).toBe(REDACTED)
    expect(result['http.method']).toBe('POST')
  })
})

// ─── Masking effectiveness test ───────────────────────────────────────────────

describe('runMaskingEffectivenessTest', () => {
  it('passes for log_message channel with default rules', () => {
    const results = runMaskingEffectivenessTest(DEFAULT_RULES, ['log_message'])
    const r = results.find((x) => x.channel === 'log_message')!
    expect(r.passed).toBe(true)
    expect(r.missedPatterns).toHaveLength(0)
  })

  it('detects unmasked patterns when rules are empty', () => {
    const results = runMaskingEffectivenessTest([], ['log_message'])
    const r = results.find((x) => x.channel === 'log_message')!
    expect(r.passed).toBe(false)
    expect(r.missedPatterns.length).toBeGreaterThan(0)
  })
})

// ─── Debug mode guard ─────────────────────────────────────────────────────────

describe('validateDebugMode', () => {
  const originalEnv = process.env.NODE_ENV

  afterEach(() => {
    Object.defineProperty(process.env, 'NODE_ENV', { value: originalEnv, writable: true })
    delete process.env.DEBUG_MODE
  })

  it('throws in production when DEBUG_MODE is true', () => {
    Object.defineProperty(process.env, 'NODE_ENV', { value: 'production', writable: true })
    process.env.DEBUG_MODE = 'true'
    expect(() => validateDebugMode()).toThrow('DEBUG_MODE must not be enabled in production')
  })

  it('does not throw in development with DEBUG_MODE true', () => {
    Object.defineProperty(process.env, 'NODE_ENV', { value: 'development', writable: true })
    process.env.DEBUG_MODE = 'true'
    expect(() => validateDebugMode()).not.toThrow()
  })

  it('does not throw in production when DEBUG_MODE is not set', () => {
    Object.defineProperty(process.env, 'NODE_ENV', { value: 'production', writable: true })
    delete process.env.DEBUG_MODE
    expect(() => validateDebugMode()).not.toThrow()
  })
})

// ─── Masking rule cache invalidation ─────────────────────────────────────────

describe('masking rule cache invalidation', () => {
  it('cache version increments on addRule', () => {
    const v0 = getCacheVersion()
    addRule({ id: 'test_rule', category: 'api_key', strategy: 'redact', channels: ['log_field'] })
    expect(getCacheVersion()).toBeGreaterThan(v0)
  })

  it('cache version increments on updateRule', () => {
    const v0 = getCacheVersion()
    updateRule('rule_auth_credential', { strategy: 'tokenise' })
    expect(getCacheVersion()).toBeGreaterThan(v0)
  })

  it('cache version increments on deleteRule', () => {
    const v0 = getCacheVersion()
    deleteRule('rule_auth_credential')
    expect(getCacheVersion()).toBeGreaterThan(v0)
  })

  it('new rule is immediately available via getRules', () => {
    addRule({ id: 'new_rule', category: 'contact_info', strategy: 'partial', channels: ['api_response'] })
    const rules = getRules()
    expect(rules.find((r) => r.id === 'new_rule')).toBeDefined()
  })

  it('deleted rule is immediately removed from getRules', () => {
    deleteRule('rule_jwt')
    expect(getRules().find((r) => r.id === 'rule_jwt')).toBeUndefined()
  })

  it('updated rule reflects patch immediately', () => {
    updateRule('rule_jwt', { strategy: 'tokenise' })
    const rule = getRules().find((r) => r.id === 'rule_jwt')
    expect(rule?.strategy).toBe('tokenise')
  })
})

// ─── Prometheus counters ──────────────────────────────────────────────────────

describe('Prometheus masking counters', () => {
  it('increments counter per category and channel', () => {
    maskLogFields({ password: 'x', token: 'y' }, DEFAULT_RULES, 'log_field')
    const counters = getMaskingCounters()
    const total = Object.values(counters).reduce((a, b) => a + b, 0)
    expect(total).toBeGreaterThanOrEqual(2)
  })

  it('resets counters correctly', () => {
    maskLogFields({ password: 'x' }, DEFAULT_RULES)
    resetMaskingCounters()
    expect(Object.keys(getMaskingCounters())).toHaveLength(0)
  })
})
