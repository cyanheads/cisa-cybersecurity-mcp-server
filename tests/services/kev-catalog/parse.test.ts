/**
 * @fileoverview Tests for pure KEV feed normalization — the `notes` parser,
 * the reference classifier, directive detection, and the raw-record mapper.
 * @module tests/services/kev-catalog/parse.test
 */

import { describe, expect, it } from 'vitest';
import {
  classifyReference,
  daysBetween,
  kevCatalogUrl,
  parseKevNotes,
  readDirective,
  toKevRecord,
} from '@/services/kev-catalog/parse.js';

describe('classifyReference', () => {
  it('classifies by recognized label first', () => {
    expect(classifyReference('https://www.cisa.gov/bod-26-04', 'BOD 26-04')).toBe('bod_guidance');
    expect(
      classifyReference('https://www.cisa.gov/forensics', 'Forensics Triage Requirements'),
    ).toBe('forensic_triage');
    expect(
      classifyReference('https://www.cisa.gov/mitigation', 'CISA Mitigation Instructions'),
    ).toBe('cisa');
  });

  it('falls back to host when no label is recognized', () => {
    expect(classifyReference('https://nvd.nist.gov/vuln/detail/CVE-2025-1')).toBe('nvd');
    expect(classifyReference('https://www.cisa.gov/some-page')).toBe('cisa');
    expect(classifyReference('https://sub.cisa.gov/some-page')).toBe('cisa');
    expect(classifyReference('https://vendor.example/advisory')).toBe('vendor');
  });

  it('returns other for a string that does not parse as a URL', () => {
    expect(classifyReference('not a url')).toBe('other');
  });
});

describe('parseKevNotes', () => {
  it('parses a labeled segment into a classified reference with its label', () => {
    const parsed = parseKevNotes('BOD 26-04: https://www.cisa.gov/bod-26-04');
    expect(parsed.references).toEqual([
      { kind: 'bod_guidance', label: 'BOD 26-04', url: 'https://www.cisa.gov/bod-26-04' },
    ]);
    expect(parsed.commentary).toBeUndefined();
  });

  it('parses a bare URL classified by host', () => {
    const parsed = parseKevNotes('https://nvd.nist.gov/vuln/detail/CVE-2025-39964');
    expect(parsed.references).toEqual([
      { kind: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-39964' },
    ]);
  });

  it('handles the shape most of the 175 empty-cwes records carry: a single NVD URL, no prose', () => {
    const parsed = parseKevNotes('https://nvd.nist.gov/vuln/detail/CVE-2025-00001');
    expect(parsed.references).toHaveLength(1);
    expect(parsed.references[0]?.kind).toBe('nvd');
    expect(parsed.commentary).toBeUndefined();
  });

  it('splits multiple semicolon-delimited segments and keeps leading prose as commentary', () => {
    const parsed = parseKevNotes(
      'Apply mitigations per vendor instructions.; https://nvd.nist.gov/vuln/detail/CVE-2025-1; CISA Mitigation Instructions: https://www.cisa.gov/mitigations',
    );
    expect(parsed.commentary).toBe('Apply mitigations per vendor instructions.');
    expect(parsed.references).toEqual([
      { kind: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-1' },
      {
        kind: 'cisa',
        label: 'CISA Mitigation Instructions',
        url: 'https://www.cisa.gov/mitigations',
      },
    ]);
  });

  it('returns no commentary and no references for an empty string', () => {
    const parsed = parseKevNotes('');
    expect(parsed).toEqual({ references: [] });
  });

  it('ignores blank segments from repeated delimiters', () => {
    const parsed = parseKevNotes(';; https://nvd.nist.gov/vuln/detail/CVE-2025-1 ;;');
    expect(parsed.references).toHaveLength(1);
  });

  /* Notes values below are verbatim from KEV catalog 2026.09.24. */
  describe('URL shapes that already parse and must keep parsing', () => {
    it('splits a `;` followed directly by a URL (CVE-2018-5430)', () => {
      const parsed = parseKevNotes(
        'https://www.tibco.com/support/advisories/2018/04/tibco-security-advisory-april-17-2018-tibco-jasperreports-2018-5430;https://nvd.nist.gov/vuln/detail/CVE-2018-5430',
      );
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://www.tibco.com/support/advisories/2018/04/tibco-security-advisory-april-17-2018-tibco-jasperreports-2018-5430',
        'https://nvd.nist.gov/vuln/detail/CVE-2018-5430',
      ]);
      expect(parsed.commentary).toBeUndefined();
    });

    it('keeps a balanced closing parenthesis that ends a URL (CVE-2020-15415)', () => {
      const draytek =
        'https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-remote-code-injection/execution-vulnerability-(cve-2020-14472)';
      const parsed = parseKevNotes(`${draytek} ; https://nvd.nist.gov/vuln/detail/CVE-2020-15415`);
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        draytek,
        'https://nvd.nist.gov/vuln/detail/CVE-2020-15415',
      ]);
    });

    it('keeps commas inside a URL that are not followed by another URL (CVE-2009-3459)', () => {
      const archived =
        'https://web.archive.org/web/20120324170253/http://www.adobe.com/support/security/bulletins/apsb09-15.html#:~:text=CVE%2D2009%2D3459).-,NOTE%3A,-There%20are%20reports';
      const parsed = parseKevNotes(
        `https://www.cisa.gov/news-events/alerts/2009/10/13/adobe-reader-and-acrobat-vulnerabilities ; ${archived} ; https://nvd.nist.gov/vuln/detail/CVE-2009-3459`,
      );
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://www.cisa.gov/news-events/alerts/2009/10/13/adobe-reader-and-acrobat-vulnerabilities',
        archived,
        'https://nvd.nist.gov/vuln/detail/CVE-2009-3459',
      ]);
      expect(parsed.references.map((ref) => ref.kind)).toEqual(['cisa', 'vendor', 'nvd']);
    });

    it('keeps the label of a `Label: URL` segment exactly', () => {
      const parsed = parseKevNotes(
        'CISA Mitigation Instructions: https://www.cisa.gov/cisa-mitigation-instructions-CVE-2025-0282 ; https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
      );
      expect(parsed.references[0]).toEqual({
        kind: 'cisa',
        label: 'CISA Mitigation Instructions',
        url: 'https://www.cisa.gov/cisa-mitigation-instructions-CVE-2025-0282',
      });
    });
  });

  describe('every URL in notes becomes a reference', () => {
    const nvd = (cveId: string) => `https://nvd.nist.gov/vuln/detail/${cveId}`;

    it('splits a comma run with a space after each comma, in notes order (CVE-2023-4966)', () => {
      const parsed = parseKevNotes(
        'https://www.netscaler.com/blog/news/cve-2023-4966-critical-security-update-now-available-for-netscaler-adc-and-netscaler-gateway/, https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967 ;  https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
      );
      expect(parsed.references).toEqual([
        {
          kind: 'vendor',
          url: 'https://www.netscaler.com/blog/news/cve-2023-4966-critical-security-update-now-available-for-netscaler-adc-and-netscaler-gateway/',
        },
        {
          kind: 'vendor',
          url: 'https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967',
        },
        { kind: 'nvd', url: nvd('CVE-2023-4966') },
      ]);
      expect(parsed.commentary).toBeUndefined();
    });

    it('splits a five-URL comma run (CVE-2024-44309)', () => {
      const parsed = parseKevNotes(
        'https://support.apple.com/en-us/121752, https://support.apple.com/en-us/121753, https://support.apple.com/en-us/121754, https://support.apple.com/en-us/121755, https://support.apple.com/en-us/121756 ; https://nvd.nist.gov/vuln/detail/CVE-2024-44309',
      );
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://support.apple.com/en-us/121752',
        'https://support.apple.com/en-us/121753',
        'https://support.apple.com/en-us/121754',
        'https://support.apple.com/en-us/121755',
        'https://support.apple.com/en-us/121756',
        nvd('CVE-2024-44309'),
      ]);
      expect(parsed.commentary).toBeUndefined();
    });

    it('splits a comma run with no space after the comma (CVE-2023-28205)', () => {
      const parsed = parseKevNotes(
        'https://support.apple.com/en-us/HT213720,https://support.apple.com/en-us/HT213721,https://support.apple.com/en-us/HT213722,https://support.apple.com/en-us/HT213723;  https://nvd.nist.gov/vuln/detail/CVE-2023-28205',
      );
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://support.apple.com/en-us/HT213720',
        'https://support.apple.com/en-us/HT213721',
        'https://support.apple.com/en-us/HT213722',
        'https://support.apple.com/en-us/HT213723',
        nvd('CVE-2023-28205'),
      ]);
    });

    it('splits a comma run that ends in a trailing comma (CVE-2023-23397)', () => {
      const parsed = parseKevNotes(
        'https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-23397, https://msrc.microsoft.com/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/, ;  https://nvd.nist.gov/vuln/detail/CVE-2023-23397',
      );
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-23397',
        'https://msrc.microsoft.com/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/',
        nvd('CVE-2023-23397'),
      ]);
      expect(parsed.commentary).toBeUndefined();
    });

    it('extracts URLs from prose, unbalanced `)` trimmed, prose kept verbatim (CVE-2021-26855)', () => {
      const prose =
        "Reference CISA's ED 21-02 (https://www.cisa.gov/news-events/directives/ed-21-02-mitigate-microsoft-exchange-premises-product-vulnerabilities) for further guidance and requirements. Note: The due date for addressing this vulnerability aligns with the requirements outlined in ED 21-02. https://nvd.nist.gov/vuln/detail/CVE-2021-26855";
      const parsed = parseKevNotes(prose);
      expect(parsed.references).toEqual([
        {
          kind: 'cisa',
          url: 'https://www.cisa.gov/news-events/directives/ed-21-02-mitigate-microsoft-exchange-premises-product-vulnerabilities',
        },
        { kind: 'nvd', url: nvd('CVE-2021-26855') },
      ]);
      expect(parsed.commentary).toBe(prose);
    });

    it('extracts URLs joined by "and" inside prose (CVE-2024-4978)', () => {
      const prose =
        'Please follow the vendor’s instructions as outlined in the public statements at https://www.rapid7.com/blog/post/2024/05/23/cve-2024-4978-backdoored-justice-av-solutions-viewer-software-used-in-apparent-supply-chain-attack#remediation and https://www.javs.com/downloads';
      const parsed = parseKevNotes(`${prose};  https://nvd.nist.gov/vuln/detail/CVE-2024-4978`);
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://www.rapid7.com/blog/post/2024/05/23/cve-2024-4978-backdoored-justice-av-solutions-viewer-software-used-in-apparent-supply-chain-attack#remediation',
        'https://www.javs.com/downloads',
        nvd('CVE-2024-4978'),
      ]);
      expect(parsed.commentary).toBe(prose);
    });

    it('extracts URLs followed by more prose, trailing `.` trimmed (CVE-2023-0669)', () => {
      const prose =
        'This CVE has a CISA AA located here: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a. Please see the AA for associated IOCs. Additional information is available at: https://my.goanywhere.com/webclient/DownloadProductFiles.xhtml. Fortra users must have an account in order to login and access the patch.';
      const parsed = parseKevNotes(`${prose};  https://nvd.nist.gov/vuln/detail/CVE-2023-0669`);
      expect(parsed.references).toEqual([
        {
          kind: 'cisa',
          url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a',
        },
        { kind: 'vendor', url: 'https://my.goanywhere.com/webclient/DownloadProductFiles.xhtml' },
        { kind: 'nvd', url: nvd('CVE-2023-0669') },
      ]);
      expect(parsed.commentary).toBe(prose);
    });

    it('extracts a URL after "please see:" and a comma run inside the same prose segment', () => {
      const parsed = parseKevNotes(
        'The patched Rejetto HTTP File Server (HFS) is version 3: https://github.com/rejetto/hfs?tab=readme-ov-file#installation, https://www.rejetto.com/hfs/ ;   https://nvd.nist.gov/vuln/detail/CVE-2024-23692',
      );
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        'https://github.com/rejetto/hfs?tab=readme-ov-file#installation',
        'https://www.rejetto.com/hfs/',
        nvd('CVE-2024-23692'),
      ]);
      expect(parsed.references.every((ref) => ref.label === undefined)).toBe(true);
      expect(parsed.commentary).toBe(
        'The patched Rejetto HTTP File Server (HFS) is version 3: https://github.com/rejetto/hfs?tab=readme-ov-file#installation, https://www.rejetto.com/hfs/',
      );
    });

    it('does not split a URL that contains `;`, in references or commentary (CVE-2023-4911)', () => {
      const glibc =
        'https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=1056e5b4c3f2d90ed2b4a55f96add28da2f4c8fa';
      const prose = `This vulnerability affects a common open-source component, third-party library, or a protocol used by different products. Please check with specific vendors for information on patching status. For more information, please see: ${glibc}, https://access.redhat.com/security/cve/cve-2023-4911, https://www.debian.org/security/2023/dsa-5514`;
      const parsed = parseKevNotes(`${prose} ; https://nvd.nist.gov/vuln/detail/CVE-2023-4911  `);
      expect(parsed.references.map((ref) => ref.url)).toEqual([
        glibc,
        'https://access.redhat.com/security/cve/cve-2023-4911',
        'https://www.debian.org/security/2023/dsa-5514',
        nvd('CVE-2023-4911'),
      ]);
      expect(parsed.commentary).toBe(prose);
    });

    it('trims a trailing `",` and a trailing `"` off a URL (CVE-2025-5419, CVE-2026-41940)', () => {
      expect(
        parseKevNotes(
          'https://chromereleases.googleblog.com/2025/06/stable-channel-update-for-desktop.html;   https://nvd.nist.gov/vuln/detail/CVE-2025-5419",',
        ),
      ).toEqual({
        references: [
          {
            kind: 'vendor',
            url: 'https://chromereleases.googleblog.com/2025/06/stable-channel-update-for-desktop.html',
          },
          { kind: 'nvd', url: nvd('CVE-2025-5419') },
        ],
      });
      expect(
        parseKevNotes(
          'https://docs.wpsquared.com/changelogs/versions/changelog/#13617 ; https://nvd.nist.gov/vuln/detail/CVE-2026-41940"',
        ).references.at(-1),
      ).toEqual({ kind: 'nvd', url: nvd('CVE-2026-41940') });
    });

    it('trims a trailing `.` off a bare URL segment (CVE-2026-50751)', () => {
      const parsed = parseKevNotes(
        'https://support.checkpoint.com/results/sk/sk185033?_gl=1*1wqeqhc*_gcl_au*MTI1MzE5MjI2LjE3ODA5MzQ1NTM. ; https://nvd.nist.gov/vuln/detail/CVE-2026-50751',
      );
      expect(parsed.references[0]?.url).toBe(
        'https://support.checkpoint.com/results/sk/sk185033?_gl=1*1wqeqhc*_gcl_au*MTI1MzE5MjI2LjE3ODA5MzQ1NTM',
      );
      expect(parsed.commentary).toBeUndefined();
    });

    it('extracts every URL from a segment carrying two labels, keeping the segment as prose (CVE-2025-0282)', () => {
      const segment =
        'CISA Mitigation Instructions: https://www.cisa.gov/cisa-mitigation-instructions-CVE-2025-0282 Additional References: https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283';
      const parsed = parseKevNotes(`${segment} ; https://nvd.nist.gov/vuln/detail/CVE-2025-0282`);
      expect(parsed.references.map((ref) => ref.kind)).toEqual(['cisa', 'vendor', 'nvd']);
      expect(parsed.commentary).toBe(segment);
    });
  });

  describe('pathological notes text', () => {
    /* `notes` is upstream text parsed on every catalog load; none of these shapes
     * may make the parse grow faster than linearly with its length. */
    const SHAPES: Record<string, (length: number) => string> = {
      'a run of (': (n) => '('.repeat(n),
      'http:// repeated with no terminator': (n) => 'http://'.repeat(Math.ceil(n / 7)),
      'a URL ending in a run of )': (n) => `https://a.example/${')'.repeat(n)}`,
      'a URL ending in ).).).': (n) => `https://a.example/${').'.repeat(n / 2)}`,
      'a URL with a punctuation run before its last character': (n) =>
        `https://a.example/${',."'.repeat(Math.ceil(n / 3))}x`,
      'a URL continued by ;x;x;x': (n) => `https://a.example/${';x'.repeat(n / 2)}`,
      'prose URLs each continued by ;y': (n) =>
        'see https://a.example/x;y '.repeat(Math.ceil(n / 26)),
    };

    /** Mean per-call wall time over `runs` calls. */
    function meanMs(notes: string, runs: number): number {
      const start = performance.now();
      for (let i = 0; i < runs; i++) parseKevNotes(notes);
      return (performance.now() - start) / runs;
    }

    /**
     * Best per-call wall time for each input, over interleaved rounds. Parallel
     * test workers contend for the CPU in bursts; back-to-back rounds of one
     * input can all land inside a single burst and skew the ratio, while
     * interleaved rounds spread both inputs across the same conditions, and one
     * clean round of each is enough.
     */
    function bestMsPair(small: string, large: string): { largeMs: number; smallMs: number } {
      let smallMs = Number.POSITIVE_INFINITY;
      let largeMs = Number.POSITIVE_INFINITY;
      for (let round = 0; round < 10; round++) {
        smallMs = Math.min(smallMs, meanMs(small, 20));
        largeMs = Math.min(largeMs, meanMs(large, 2));
      }
      return { smallMs: Math.max(smallMs, 0.02), largeMs };
    }

    it.each(Object.entries(SHAPES))(
      '%s parses in linear time',
      (_label, build) => {
        const small = build(5_000);
        const large = build(80_000);
        parseKevNotes(small);
        parseKevNotes(large);
        const { smallMs, largeMs } = bestMsPair(small, large);
        /* 16x the input: linear growth is ~16x, quadratic ~256x. */
        expect(largeMs / smallMs).toBeLessThan(64);
        expect(largeMs).toBeLessThan(100);
      },
      60_000,
    );
  });
});

describe('readDirective', () => {
  it('reads BOD 26-04 when present', () => {
    expect(readDirective('Apply updates per BOD 26-04.', '')).toBe('BOD 26-04');
  });

  it('reads BOD 22-01 when present and 26-04 is absent', () => {
    expect(readDirective('', 'Cited under BOD 22-01.')).toBe('BOD 22-01');
  });

  it('prefers BOD 26-04 when both are cited', () => {
    expect(readDirective('BOD 22-01 superseded by BOD 26-04.', '')).toBe('BOD 26-04');
  });

  it('returns null when neither directive is cited — never inferred from age', () => {
    expect(
      readDirective(
        'Apply updates per vendor instructions.',
        'https://nvd.nist.gov/vuln/detail/CVE-2020-1',
      ),
    ).toBeNull();
  });
});

describe('toKevRecord', () => {
  it('maps a full raw record to the domain shape', () => {
    const record = toKevRecord({
      cveID: 'cve-2026-12345',
      vendorProject: ' Acme ',
      product: 'Widget',
      vulnerabilityName: 'Acme Widget RCE',
      dateAdded: '2026-09-10',
      shortDescription: 'Acme Widget contains a vulnerability.',
      requiredAction: 'Apply mitigations per BOD 26-04.',
      dueDate: '2026-09-13',
      knownRansomwareCampaignUse: 'Known',
      forensicTriage: 'Yes',
      cwes: ['CWE-20', 'CWE-89'],
      notes: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
    });
    expect(record).toMatchObject({
      cveId: 'CVE-2026-12345',
      vendorProject: 'Acme',
      product: 'Widget',
      dateAdded: '2026-09-10',
      dueDate: '2026-09-13',
      knownRansomwareCampaignUse: 'Known',
      forensicTriage: 'Yes',
      cwes: ['CWE-20', 'CWE-89'],
      directive: 'BOD 26-04',
    });
    expect(record?.kevUrl).toBe(kevCatalogUrl('CVE-2026-12345'));
    expect(record?.notesCommentary).toBeUndefined();
  });

  it('returns null when the record carries no CVE ID', () => {
    expect(toKevRecord({ vendorProject: 'Acme' })).toBeNull();
  });

  it('defaults knownRansomwareCampaignUse to Unknown and forensicTriage to No for any other value', () => {
    const record = toKevRecord({
      cveID: 'CVE-2026-0001',
      dateAdded: '2026-01-01',
      dueDate: '2026-01-22',
      knownRansomwareCampaignUse: '',
      forensicTriage: '',
    });
    expect(record?.knownRansomwareCampaignUse).toBe('Unknown');
    expect(record?.forensicTriage).toBe('No');
  });

  it('defaults cwes to an empty array when absent or malformed', () => {
    const base = { cveID: 'CVE-2026-0001', dateAdded: '2026-01-01', dueDate: '2026-01-22' };
    expect(toKevRecord(base)?.cwes).toEqual([]);
    expect(toKevRecord({ ...base, cwes: 'not-an-array' })?.cwes).toEqual([]);
  });

  it('drops a cwes entry that is not a CWE identifier', () => {
    const record = toKevRecord({
      cveID: 'CVE-2026-0001',
      dateAdded: '2026-01-01',
      dueDate: '2026-01-22',
      cwes: ['CWE-20', 'not a cwe', '', 'CWE-79'],
    });
    expect(record?.cwes).toEqual(['CWE-20', 'CWE-79']);
  });

  it('returns null for a record whose identity or deadline fields are not in the advertised shape', () => {
    const dates = { dateAdded: '2026-01-01', dueDate: '2026-01-22' };
    expect(toKevRecord({ cveID: 'CVE-2026-1', ...dates })).toBeNull();
    expect(toKevRecord({ cveID: 'not-a-cve', ...dates })).toBeNull();
    expect(toKevRecord({ cveID: 'CVE-2026-0001', dueDate: '2026-01-22' })).toBeNull();
    expect(
      toKevRecord({ cveID: 'CVE-2026-0001', dateAdded: '2026-01-01', dueDate: 'soon' }),
    ).toBeNull();
  });

  it('carries notesCommentary when the notes field opens with prose', () => {
    const record = toKevRecord({
      cveID: 'CVE-2026-0001',
      dateAdded: '2026-01-01',
      dueDate: '2026-01-22',
      notes: 'Exploited in the wild.; https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    });
    expect(record?.notesCommentary).toBe('Exploited in the wild.');
  });
});

describe('daysBetween', () => {
  it('computes whole calendar days forward and backward', () => {
    expect(daysBetween('2026-09-10', '2026-09-13')).toBe(3);
    expect(daysBetween('2026-09-13', '2026-09-10')).toBe(-3);
    expect(daysBetween('2026-09-10', '2026-09-10')).toBe(0);
  });

  it('returns 0 for unparseable dates rather than throwing', () => {
    expect(daysBetween('not-a-date', '2026-09-10')).toBe(0);
  });
});
