import { MaskingRule, DEFAULT_RULES } from './masking'

// In-memory rule store — replace backing with Redis in production.
// Cache invalidation is immediate: all rule reads go through getRules().

const _ruleStore: Map<string, MaskingRule> = new Map(
  DEFAULT_RULES.map((r) => [r.id, r])
)

let _cacheVersion = 0

export function getCacheVersion(): number {
  return _cacheVersion
}

function invalidateCache(): void {
  _cacheVersion++
}

export function getRules(): MaskingRule[] {
  return Array.from(_ruleStore.values())
}

export function getRuleById(id: string): MaskingRule | undefined {
  return _ruleStore.get(id)
}

export function addRule(rule: Omit<MaskingRule, 'createdAt' | 'updatedAt'>): MaskingRule {
  const now = new Date().toISOString()
  const full: MaskingRule = { ...rule, createdAt: now, updatedAt: now }
  _ruleStore.set(full.id, full)
  invalidateCache()
  return full
}

export function updateRule(id: string, patch: Partial<Omit<MaskingRule, 'id' | 'createdAt'>>): MaskingRule | null {
  const existing = _ruleStore.get(id)
  if (!existing) return null
  const updated: MaskingRule = { ...existing, ...patch, id, updatedAt: new Date().toISOString() }
  _ruleStore.set(id, updated)
  invalidateCache()
  return updated
}

export function deleteRule(id: string): boolean {
  const existed = _ruleStore.has(id)
  _ruleStore.delete(id)
  if (existed) invalidateCache()
  return existed
}

export function resetRuleStore(): void {
  _ruleStore.clear()
  for (const r of DEFAULT_RULES) _ruleStore.set(r.id, r)
  invalidateCache()
}
