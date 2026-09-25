# cisa-cybersecurity-mcp-server - Directory Structure

Generated on: 2026-09-25 12:41:20

```text
cisa-cybersecurity-mcp-server/
├── .claude-plugin/
│   └── plugin.json
├── .codex-plugin/
│   ├── mcp.json
│   └── plugin.json
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── config.yml
│   │   └── feature_request.yml
│   ├── workflows/
│   │   └── codeql.yml
│   ├── CODE_OF_CONDUCT.md
│   ├── CONTRIBUTING.md
│   ├── FUNDING.yml
│   └── SECURITY.md
├── .vscode/
│   ├── extensions.json
│   └── settings.json
├── changelog/
│   ├── 0.1.x/
│   ├── 0.2.x/
│   └── template.md
├── docs/
│   └── design.md
├── framework-skills/
│   ├── add-app-tool/
│   │   └── SKILL.md
│   ├── add-prompt/
│   │   └── SKILL.md
│   ├── add-resource/
│   │   └── SKILL.md
│   ├── add-service/
│   │   └── SKILL.md
│   ├── add-test/
│   │   └── SKILL.md
│   ├── add-tool/
│   │   └── SKILL.md
│   ├── api-auth/
│   │   └── SKILL.md
│   ├── api-canvas/
│   │   └── SKILL.md
│   ├── api-config/
│   │   └── SKILL.md
│   ├── api-context/
│   │   └── SKILL.md
│   ├── api-errors/
│   │   └── SKILL.md
│   ├── api-linter/
│   │   └── SKILL.md
│   ├── api-mirror/
│   │   └── SKILL.md
│   ├── api-services/
│   │   ├── references/
│   │   │   ├── graph.md
│   │   │   ├── llm.md
│   │   │   └── speech.md
│   │   └── SKILL.md
│   ├── api-telemetry/
│   │   └── SKILL.md
│   ├── api-testing/
│   │   └── SKILL.md
│   ├── api-utils/
│   │   ├── references/
│   │   │   ├── formatting.md
│   │   │   ├── parsing.md
│   │   │   └── security.md
│   │   └── SKILL.md
│   ├── api-workers/
│   │   └── SKILL.md
│   ├── code-simplifier/
│   │   └── SKILL.md
│   ├── design-mcp-server/
│   │   └── SKILL.md
│   ├── field-test/
│   │   └── SKILL.md
│   ├── git-wrapup/
│   │   └── SKILL.md
│   ├── maintenance/
│   │   └── SKILL.md
│   ├── orchestrations/
│   │   ├── workflows/
│   │   │   ├── field-test-fix.md
│   │   │   ├── fix-wrapup-release.md
│   │   │   ├── greenfield-build.md
│   │   │   └── maintenance-release.md
│   │   └── SKILL.md
│   ├── polish-docs-meta/
│   │   ├── references/
│   │   │   ├── agent-protocol.md
│   │   │   ├── package-meta.md
│   │   │   ├── readme.md
│   │   │   └── server-json.md
│   │   └── SKILL.md
│   ├── release-and-publish/
│   │   └── SKILL.md
│   ├── release-pr-review/
│   │   └── SKILL.md
│   ├── report-issue-framework/
│   │   └── SKILL.md
│   ├── report-issue-local/
│   │   └── SKILL.md
│   ├── security-pass/
│   │   └── SKILL.md
│   ├── setup/
│   │   └── SKILL.md
│   ├── techniques/
│   │   ├── references/
│   │   │   └── outline-on-overflow.md
│   │   └── SKILL.md
│   └── tool-defs-analysis/
│       └── SKILL.md
├── scripts/
│   ├── _mirror-context.ts
│   ├── build-changelog.ts
│   ├── build.ts
│   ├── check-dependency-specifiers.ts
│   ├── check-docs-sync.ts
│   ├── check-framework-antipatterns.ts
│   ├── check-skill-versions.ts
│   ├── check-skills-sync.ts
│   ├── clean-mcpb.ts
│   ├── clean.ts
│   ├── csaf-mirror-init.ts
│   ├── csaf-mirror-refresh.ts
│   ├── csaf-mirror-verify.ts
│   ├── devcheck.ts
│   ├── lint-mcp.ts
│   ├── lint-packaging.ts
│   ├── list-skills.ts
│   ├── release-github.ts
│   └── tree.ts
├── src/
│   ├── config/
│   │   └── server-config.ts
│   ├── mcp-server/
│   │   ├── resources/
│   │   │   └── definitions/
│   │   │       ├── ics-advisory.resource.ts
│   │   │       ├── index.ts
│   │   │       └── kev-entry.resource.ts
│   │   ├── schemas/
│   │   │   ├── advisory.ts
│   │   │   └── kev-record.ts
│   │   └── tools/
│   │       └── definitions/
│   │           ├── check-cve-status.tool.ts
│   │           ├── get-advisory.tool.ts
│   │           ├── get-alerts.tool.ts
│   │           ├── get-ssvc.tool.ts
│   │           ├── index.ts
│   │           ├── list-reference.tool.ts
│   │           ├── search-ics-advisories.tool.ts
│   │           └── search-kev.tool.ts
│   ├── reference/
│   │   ├── bod-2604.ts
│   │   ├── cvss.ts
│   │   ├── sectors.ts
│   │   └── tables.ts
│   ├── services/
│   │   ├── cisa-feeds/
│   │   │   ├── cisa-feeds-service.ts
│   │   │   ├── normalize.ts
│   │   │   └── types.ts
│   │   ├── csaf-mirror/
│   │   │   ├── csaf-mirror-service.ts
│   │   │   ├── ingest.ts
│   │   │   ├── normalize.ts
│   │   │   ├── schema.ts
│   │   │   ├── tar.ts
│   │   │   └── types.ts
│   │   ├── kev-catalog/
│   │   │   ├── kev-catalog-service.ts
│   │   │   ├── parse.ts
│   │   │   └── types.ts
│   │   ├── vulnrichment/
│   │   │   ├── paths.ts
│   │   │   ├── types.ts
│   │   │   └── vulnrichment-service.ts
│   │   ├── search-text.ts
│   │   └── upstream-http.ts
│   └── index.ts
├── tests/
│   ├── fixtures/
│   │   ├── csaf-documents.ts
│   │   ├── kev-feed.ts
│   │   ├── rss-feeds.ts
│   │   ├── tar.ts
│   │   └── vulnrichment-records.ts
│   ├── fuzz/
│   │   └── tools.fuzz.test.ts
│   ├── helpers/
│   │   ├── catalog-counts.ts
│   │   ├── emitted-schema.ts
│   │   └── format-text.ts
│   ├── integration/
│   │   └── csaf-mirror.test.ts
│   ├── mcp-server/
│   │   ├── resources/
│   │   │   └── definitions/
│   │   │       ├── ics-advisory.resource.test.ts
│   │   │       └── kev-entry.resource.test.ts
│   │   ├── schemas/
│   │   │   ├── advisory.test.ts
│   │   │   └── kev-record.test.ts
│   │   └── tools/
│   │       └── definitions/
│   │           ├── check-cve-status.tool.test.ts
│   │           ├── get-advisory.tool.test.ts
│   │           ├── get-alerts.tool.test.ts
│   │           ├── get-ssvc.tool.test.ts
│   │           ├── list-reference.tool.test.ts
│   │           ├── search-ics-advisories.tool.test.ts
│   │           └── search-kev.tool.test.ts
│   ├── reference/
│   │   ├── bod-2604.test.ts
│   │   ├── cvss.test.ts
│   │   └── sectors.test.ts
│   ├── services/
│   │   ├── cisa-feeds/
│   │   │   ├── cisa-feeds-service.test.ts
│   │   │   └── normalize.test.ts
│   │   ├── csaf-mirror/
│   │   │   ├── normalize.test.ts
│   │   │   └── tar.test.ts
│   │   ├── kev-catalog/
│   │   │   ├── kev-catalog-service.test.ts
│   │   │   └── parse.test.ts
│   │   ├── vulnrichment/
│   │   │   ├── paths.test.ts
│   │   │   └── vulnrichment-service.test.ts
│   │   └── upstream-http.test.ts
│   └── smoke/
│       └── surface.test.ts
├── .dockerignore
├── .env.example
├── .gitattributes
├── .gitignore
├── .mcpbignore
├── AGENTS.md
├── biome.json
├── bun.lock
├── bunfig.toml
├── CHANGELOG.md
├── CLAUDE.md
├── devcheck.config.json
├── Dockerfile
├── LICENSE
├── manifest.json
├── package.json
├── README.md
├── server.json
├── tsconfig.build.json
├── tsconfig.json
└── vitest.config.ts
```

_Note: This tree excludes files and directories matched by .gitignore and default patterns._
