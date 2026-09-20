/**
 * @fileoverview Tests for Vulnrichment path composition — the `<year>/<block>/`
 * sharding scheme and the `develop`-branch URL builder.
 * @module tests/services/vulnrichment/paths.test
 */

import { describe, expect, it } from 'vitest';
import {
  cveToVulnrichmentPath,
  cveToVulnrichmentUrl,
  VULNRICHMENT_BASE,
} from '@/services/vulnrichment/paths.js';

describe('cveToVulnrichmentPath', () => {
  it('replaces the last three digits of the numeric part with xxx', () => {
    expect(cveToVulnrichmentPath('CVE-2025-39964')).toBe('2025/39xxx/CVE-2025-39964.json');
  });

  it('handles a short numeric part (fewer than three trailing digits available)', () => {
    expect(cveToVulnrichmentPath('CVE-2026-8452')).toBe('2026/8xxx/CVE-2026-8452.json');
  });

  it('returns null for an input that is not a CVE ID', () => {
    expect(cveToVulnrichmentPath('not-a-cve')).toBeNull();
    expect(cveToVulnrichmentPath('CVE-25-1')).toBeNull();
  });

  it('is case-insensitive on the CVE- prefix', () => {
    expect(cveToVulnrichmentPath('cve-2025-1234')).toBe('2025/1xxx/CVE-2025-1234.json');
  });
});

describe('cveToVulnrichmentUrl', () => {
  it('composes the full raw-content URL on the develop branch', () => {
    expect(cveToVulnrichmentUrl('CVE-2025-39964')).toBe(
      `${VULNRICHMENT_BASE}/2025/39xxx/CVE-2025-39964.json`,
    );
    expect(VULNRICHMENT_BASE).toContain('/develop');
  });

  it('returns null for a non-CVE input', () => {
    expect(cveToVulnrichmentUrl('garbage')).toBeNull();
  });
});
