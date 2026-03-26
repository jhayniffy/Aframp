// ─── Masking Strategies ──────────────────────────────────────────────────────

export type MaskingStrategy = 'redact' | 'partial' | 'format_preserve' | 'tokenise'
export type OutputChannel = 'log_field' | 'log_message' | 'api_error' | 'api_response' | 'tracing' | 'metrics' | 'db_query'
export type SensitiveCategory =
  | 'auth_credential'
  | 'crypto_key'
  | 'government_id'
  | 'financial_account'
  | 'contact_info'
  | 'wallet_private_key'
  | 'jwt_token'
  | 'api_key'

export interface MaskingRule {
  id: string
  category: SensitiveCategory
  strategy: MaskingStrategy
  channels: OutputChannel[]
  fieldNames?: string[]       // for structured field masking
  pattern?: RegExp            // for unstructured string scanning
  patternSource?: string      // serialisable form of pattern
  createdAt: string
  updatedAt: string
}

export interface MaskingEvent {
  fieldName?: string
  category: SensitiveCategory
  strategy: MaskingStrategy
  channel: OutputChannel
  timestamp: string
}

// ─── Redaction Placeholder ───────────────────────────────────────────────────

export const REDACTED = '[REDACTED]'

// ─── Sensitive Field Name Registry ───────────────────────────────────────────

export const SENSITIVE_FIELD_NAMES: string[] = [
  'password', 'passwd', 'secret', 'token', 'access_token', 'refresh_token',
  'authorization', 'api_key', 'apikey', 'private_key', 'privatekey',
  'mnemonic', 'seed_phrase', 'seedphrase', 'wallet_key', 'walletkey',
  'id_number', 'national_id', 'passport_number', 'document_number',
  'account_number', 'bank_account', 'card_number', 'cvv', 'pin',
  'mobile_money', 'phone_number', 'email', 'ssn', 'tax_id',
  'cnGN_private_key', 'stellar_secret', 'stellar_private',
]

// ─── Default Masking Rules ────────────────────────────────────────────────────

export const DEFAULT_RULES: MaskingRule[] = [
  {
    id: 'rule_auth_credential',
    category: 'auth_credential',
    strategy: 'redact',
    channels: ['log_field', 'log_message', 'api_error', 'api_response', 'tracing', 'metrics', 'db_query'],
    fieldNames: ['password', 'passwd', 'secret', 'token', 'access_token', 'refresh_token', 'authorization'],
    patternSource: '(?:Bearer\\s+)[A-Za-z0-9\\-._~+/]+=*',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_jwt',
    category: 'jwt_token',
    strategy: 'redact',
    channels: ['log_field', 'log_message', 'api_error', 'tracing'],
    patternSource: 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_api_key',
    category: 'api_key',
    strategy: 'redact',
    channels: ['log_field', 'log_message', 'api_error', 'tracing'],
    fieldNames: ['api_key', 'apikey'],
    patternSource: '(?:api[_-]?key|apikey)[=:\\s]+[A-Za-z0-9\\-_]{16,}',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_private_key_pem',
    category: 'crypto_key',
    strategy: 'redact',
    channels: ['log_field', 'log_message', 'api_error', 'tracing', 'db_query'],
    fieldNames: ['private_key', 'privatekey', 'mnemonic', 'seed_phrase', 'seedphrase', 'wallet_key', 'walletkey', 'cnGN_private_key', 'stellar_secret', 'stellar_private'],
    patternSource: '-----BEGIN[\\s\\S]+?PRIVATE KEY-----[\\s\\S]+?-----END[\\s\\S]+?PRIVATE KEY-----',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_government_id',
    category: 'government_id',
    strategy: 'redact',
    channels: ['log_field', 'log_message', 'api_response', 'tracing', 'db_query'],
    fieldNames: ['id_number', 'national_id', 'passport_number', 'document_number', 'ssn', 'tax_id'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_financial_account',
    category: 'financial_account',
    strategy: 'partial',
    channels: ['log_field', 'api_response', 'tracing'],
    fieldNames: ['account_number', 'bank_account', 'card_number', 'cvv', 'pin', 'mobile_money'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_contact_info',
    category: 'contact_info',
    strategy: 'partial',
    channels: ['log_field', 'log_message', 'api_response', 'tracing'],
    fieldNames: ['phone_number', 'email'],
    patternSource: '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'rule_credit_card',
    category: 'financial_account',
    strategy: 'partial',
    channels: ['log_message', 'api_error'],
    patternSource: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
]

// ─── Masking Counters (Prometheus-compatible) ─────────────────────────────────

const _counters: Record<string, number> = {}

export function incrementMaskingCounter(category: SensitiveCategory, channel: OutputChannel): void {
  const key = `masking_events_total{category="${category}",channel="${channel}"}`
  _counters[key] = (_counters[key] ?? 0) + 1
}

export function getMaskingCounters(): Record<string, number> {
  return { ..._counters }
}

export function resetMaskingCounters(): void {
  for (const k of Object.keys(_counters)) delete _counters[k]
}

// ─── Masking Audit Log ────────────────────────────────────────────────────────

const _auditLog: MaskingEvent[] = []

export function recordMaskingEvent(event: MaskingEvent): void {
  _auditLog.push(event)
  incrementMaskingCounter(event.category, event.channel)
}

export function getMaskingAuditLog(): MaskingEvent[] {
  return [..._auditLog]
}

export function resetMaskingAuditLog(): void {
  _auditLog.length = 0
}

// ─── Strategy Implementations ─────────────────────────────────────────────────

export function applyRedact(_value: string): string {
  return REDACTED
}

export function applyPartialMask(value: string, type: 'bank_account' | 'mobile_money' | 'email' | 'default' = 'default'): string {
  if (type === 'bank_account') return `****${value.slice(-4)}`
  if (type === 'mobile_money') return `****${value.slice(-3)}`
  if (type === 'email') {
    const [local, domain] = value.split('@')
    if (!domain) return REDACTED
    return `${local[0]}***@${domain}`
  }
  if (value.length <= 4) return REDACTED
  return `${'*'.repeat(value.length - 4)}${value.slice(-4)}`
}

export function applyFormatPreserve(value: string): string {
  return value.replace(/[a-zA-Z0-9]/g, '*')
}

export function applyTokenise(value: string): string {
  // Deterministic token — hash-like but reversible only with the key (simplified for frontend)
  let hash = 0
  for (let i = 0; i < value.length; i++) {
    hash = (hash << 5) - hash + value.charCodeAt(i)
    hash |= 0
  }
  return `tok_${Math.abs(hash).toString(36).padStart(8, '0')}`
}

export function applyStrategy(value: string, strategy: MaskingStrategy, category?: SensitiveCategory): string {
  switch (strategy) {
    case 'redact': return applyRedact(value)
    case 'partial': {
      if (category === 'financial_account') {
        // Heuristic: mobile money numbers are ≤11 digits, bank accounts are longer
        const digits = value.replace(/\D/g, '')
        return digits.length <= 11
          ? applyPartialMask(value, 'mobile_money')
          : applyPartialMask(value, 'bank_account')
      }
      if (category === 'contact_info') return applyPartialMask(value, 'email')
      return applyPartialMask(value)
    }
    case 'format_preserve': return applyFormatPreserve(value)
    case 'tokenise': return applyTokenise(value)
    default: return REDACTED
  }
}

// ─── Structured Log Field Masking ─────────────────────────────────────────────

function isFieldSensitive(fieldName: string, rules: MaskingRule[]): MaskingRule | undefined {
  const lower = fieldName.toLowerCase()
  return rules.find(
    (r) => r.fieldNames?.some((f) => f.toLowerCase() === lower)
  )
}

export function maskLogFields(
  obj: Record<string, unknown>,
  rules: MaskingRule[],
  channel: OutputChannel = 'log_field',
  _path = ''
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(obj)) {
    const rule = isFieldSensitive(key, rules)
    if (rule && rule.channels.includes(channel)) {
      const masked = applyStrategy(String(value ?? ''), rule.strategy, rule.category)
      recordMaskingEvent({ fieldName: key, category: rule.category, strategy: rule.strategy, channel, timestamp: new Date().toISOString() })
      result[key] = masked
    } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = maskLogFields(value as Record<string, unknown>, rules, channel, `${_path}${key}.`)
    } else {
      result[key] = value
    }
  }
  return result
}

// ─── Unstructured Log Message Pattern Scanner ─────────────────────────────────

export interface PatternScanResult {
  masked: string
  detected: boolean
  matchedRules: string[]
}

export function scanAndMaskMessage(message: string, rules: MaskingRule[], channel: OutputChannel = 'log_message'): PatternScanResult {
  let masked = message
  let detected = false
  const matchedRules: string[] = []

  for (const rule of rules) {
    if (!rule.patternSource) continue
    if (!rule.channels.includes(channel)) continue
    const regex = new RegExp(rule.patternSource, 'gi')
    if (regex.test(masked)) {
      detected = true
      matchedRules.push(rule.id)
      masked = masked.replace(new RegExp(rule.patternSource, 'gi'), REDACTED)
      recordMaskingEvent({ category: rule.category, strategy: rule.strategy, channel, timestamp: new Date().toISOString() })
    }
  }

  return { masked, detected, matchedRules }
}

// ─── API Error Response Redaction ─────────────────────────────────────────────

const INTERNAL_ERROR_FIELDS = ['stack', 'stackTrace', 'stack_trace', 'dbError', 'db_error', 'providerError', 'provider_error', 'internalMessage', 'internal_message', 'query', 'detail']

export function redactErrorResponse(
  body: Record<string, unknown>,
  isProduction: boolean,
  rules: MaskingRule[]
): Record<string, unknown> {
  const safe: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body)) {
    if (INTERNAL_ERROR_FIELDS.includes(key)) continue
    const rule = isFieldSensitive(key, rules)
    if (rule) {
      safe[key] = applyStrategy(String(value ?? ''), rule.strategy, rule.category)
    } else {
      safe[key] = value
    }
  }
  if (isProduction) {
    // Strip any remaining internal detail — only keep code + message
    return {
      code: safe.code ?? 'INTERNAL_ERROR',
      message: safe.message ?? 'An error occurred. Please try again.',
    }
  }
  return safe
}

// ─── API Response Body Partial Masking ───────────────────────────────────────

export interface ResponseMaskingPolicy {
  [fieldName: string]: { strategy: MaskingStrategy; category: SensitiveCategory }
}

export const DEFAULT_RESPONSE_POLICY: ResponseMaskingPolicy = {
  account_number: { strategy: 'partial', category: 'financial_account' },
  bank_account:   { strategy: 'partial', category: 'financial_account' },
  mobile_money:   { strategy: 'partial', category: 'financial_account' },
  card_number:    { strategy: 'partial', category: 'financial_account' },
  document_number:{ strategy: 'redact',  category: 'government_id' },
  id_number:      { strategy: 'redact',  category: 'government_id' },
  national_id:    { strategy: 'redact',  category: 'government_id' },
  passport_number:{ strategy: 'redact',  category: 'government_id' },
  email:          { strategy: 'partial', category: 'contact_info' },
  phone_number:   { strategy: 'partial', category: 'contact_info' },
}

export function maskResponseBody(
  body: Record<string, unknown>,
  policy: ResponseMaskingPolicy = DEFAULT_RESPONSE_POLICY
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body)) {
    const rule = policy[key.toLowerCase()] ?? policy[key]
    if (rule && value !== null && value !== undefined) {
      result[key] = applyStrategy(String(value), rule.strategy, rule.category)
      recordMaskingEvent({ fieldName: key, category: rule.category, strategy: rule.strategy, channel: 'api_response', timestamp: new Date().toISOString() })
    } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = maskResponseBody(value as Record<string, unknown>, policy)
    } else {
      result[key] = value
    }
  }
  return result
}

// ─── Tracing / Span Attribute Masking ────────────────────────────────────────

export function maskSpanAttributes(
  attributes: Record<string, unknown>,
  rules: MaskingRule[]
): Record<string, unknown> {
  return maskLogFields(attributes, rules, 'tracing')
}

// ─── Masking Effectiveness Test ───────────────────────────────────────────────

export interface EffectivenessResult {
  channel: OutputChannel
  passed: boolean
  detectedCount: number
  missedPatterns: string[]
  testedAt: string
}

const SYNTHETIC_SENSITIVE: Array<{ label: string; value: string; patternSource: string }> = [
  { label: 'jwt', value: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123', patternSource: 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+' },
  { label: 'email', value: 'test@example.com', patternSource: '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}' },
  { label: 'credit_card', value: '4111111111111111', patternSource: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b' },
  { label: 'pem_key', value: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----', patternSource: '-----BEGIN[\\s\\S]+?PRIVATE KEY-----[\\s\\S]+?-----END[\\s\\S]+?PRIVATE KEY-----' },
]

export function runMaskingEffectivenessTest(rules: MaskingRule[], channels: OutputChannel[]): EffectivenessResult[] {
  return channels.map((channel) => {
    const missed: string[] = []
    let detected = 0

    for (const synthetic of SYNTHETIC_SENSITIVE) {
      const { masked } = scanAndMaskMessage(synthetic.value, rules, channel)
      const stillPresent = new RegExp(synthetic.patternSource, 'i').test(masked)
      if (stillPresent) {
        missed.push(synthetic.label)
      } else {
        detected++
      }
    }

    return {
      channel,
      passed: missed.length === 0,
      detectedCount: detected,
      missedPatterns: missed,
      testedAt: new Date().toISOString(),
    }
  })
}

// ─── Debug Mode Guard ─────────────────────────────────────────────────────────

export function validateDebugMode(): void {
  const isProduction = process.env.NODE_ENV === 'production'
  const debugEnabled = process.env.NEXT_PUBLIC_DEBUG_MODE === 'true' || process.env.DEBUG_MODE === 'true'
  if (isProduction && debugEnabled) {
    throw new Error('FATAL: DEBUG_MODE must not be enabled in production. Aborting startup.')
  }
}
