/**
 * @fileoverview Tests for the server config — the refresh cron values (default,
 * valid expression, the `off` disable value, and an invalid expression failing
 * startup) and the advisory index path (an explicit value used as given, and the
 * per-user cache default resolved from the injected host, never the real one).
 * @module tests/config/server-config.test
 */

import { tmpdir } from 'node:os';
import { isAbsolute, posix } from 'node:path';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CRON_OFF,
  defaultCsafMirrorPath,
  getServerConfig,
  resetServerConfig,
} from '@/config/server-config.js';

describe('server config', () => {
  beforeEach(() => {
    resetServerConfig();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    resetServerConfig();
  });

  describe('CISA_CSAF_MIRROR_PATH', () => {
    it('uses an explicitly set path exactly as given, relative or absolute', () => {
      for (const path of ['/tmp/somewhere/csaf.sqlite3', 'relative/dir/index.sqlite3']) {
        resetServerConfig();
        vi.stubEnv('CISA_CSAF_MIRROR_PATH', path);
        expect(getServerConfig().csafMirrorPath).toBe(path);
      }
    });

    it('unset or blank, resolves to an absolute per-user cache path, the same from any working directory', () => {
      const original = process.cwd();
      const resolved: string[] = [];
      try {
        for (const [cwd, value] of [
          ['/', undefined],
          [tmpdir(), ''],
          [original, '  '],
        ] as const) {
          process.chdir(cwd);
          resetServerConfig();
          vi.stubEnv('CISA_CSAF_MIRROR_PATH', value);
          resolved.push(getServerConfig().csafMirrorPath);
        }
      } finally {
        process.chdir(original);
      }
      expect(new Set(resolved).size).toBe(1);
      expect(isAbsolute(resolved[0] as string)).toBe(true);
      expect(resolved[0]).toMatch(/[/\\]cisa-cybersecurity-mcp-server[/\\]csaf\.sqlite3$/);
      expect(resolved[0]).not.toContain('.mirror');
    });
  });

  describe('defaultCsafMirrorPath', () => {
    const tail = ['cisa-cybersecurity-mcp-server', 'csaf.sqlite3'];

    it('macOS: ~/Library/Caches, ignoring XDG_CACHE_HOME', () => {
      expect(
        defaultCsafMirrorPath({
          platform: 'darwin',
          env: { XDG_CACHE_HOME: '/xdg' },
          homedir: '/Users/someone',
        }),
      ).toBe(posix.join('/Users/someone/Library/Caches', ...tail));
    });

    it('Linux: $XDG_CACHE_HOME when it is absolute, else ~/.cache', () => {
      const linux = (env: Record<string, string | undefined>) =>
        defaultCsafMirrorPath({ platform: 'linux', env, homedir: '/home/someone' });
      expect(linux({ XDG_CACHE_HOME: '/var/cache/someone' })).toBe(
        posix.join('/var/cache/someone', ...tail),
      );
      /* The XDG spec says a relative value is invalid and must be ignored. */
      expect(linux({ XDG_CACHE_HOME: 'relative/cache' })).toBe(
        posix.join('/home/someone/.cache', ...tail),
      );
      expect(linux({ XDG_CACHE_HOME: '' })).toBe(posix.join('/home/someone/.cache', ...tail));
      expect(linux({})).toBe(posix.join('/home/someone/.cache', ...tail));
    });

    it('other Unix platforms follow the XDG rule', () => {
      expect(
        defaultCsafMirrorPath({ platform: 'freebsd', env: {}, homedir: '/usr/home/someone' }),
      ).toBe(posix.join('/usr/home/someone/.cache', ...tail));
    });

    it('Windows: %LOCALAPPDATA%, else the profile AppData\\Local, with Windows separators', () => {
      expect(
        defaultCsafMirrorPath({
          platform: 'win32',
          env: { LOCALAPPDATA: 'C:\\Users\\someone\\AppData\\Local' },
          homedir: 'C:\\Users\\someone',
        }),
      ).toBe('C:\\Users\\someone\\AppData\\Local\\cisa-cybersecurity-mcp-server\\csaf.sqlite3');
      expect(
        defaultCsafMirrorPath({ platform: 'win32', env: {}, homedir: 'C:\\Users\\someone' }),
      ).toBe('C:\\Users\\someone\\AppData\\Local\\cisa-cybersecurity-mcp-server\\csaf.sqlite3');
    });
  });

  describe('refresh crons', () => {
    it('unset, empty, and whitespace-only values take the defaults', () => {
      for (const value of [undefined, '', '   ']) {
        resetServerConfig();
        vi.stubEnv('CISA_KEV_REFRESH_CRON', value);
        vi.stubEnv('CISA_CSAF_REFRESH_CRON', value);
        const config = getServerConfig();
        expect(config.kevRefreshCron).toBe('*/30 * * * *');
        expect(config.csafRefreshCron).toBe('17 */6 * * *');
      }
    });

    it('a valid expression passes through', () => {
      vi.stubEnv('CISA_KEV_REFRESH_CRON', '*/5 * * * *');
      vi.stubEnv('CISA_CSAF_REFRESH_CRON', '0 3 * * 1');
      const config = getServerConfig();
      expect(config.kevRefreshCron).toBe('*/5 * * * *');
      expect(config.csafRefreshCron).toBe('0 3 * * 1');
    });

    it('off, in any case and with surrounding whitespace, reads as the disable value', () => {
      for (const value of ['off', 'OFF', ' Off ', '\toff\n']) {
        resetServerConfig();
        vi.stubEnv('CISA_KEV_REFRESH_CRON', value);
        vi.stubEnv('CISA_CSAF_REFRESH_CRON', value);
        const config = getServerConfig();
        expect(config.kevRefreshCron, JSON.stringify(value)).toBe('off');
        expect(config.csafRefreshCron, JSON.stringify(value)).toBe('off');
      }
      expect(CRON_OFF).toBe('off');
    });

    it('an invalid expression fails startup with a ConfigurationError naming the variable', () => {
      for (const [variable, value] of [
        ['CISA_KEV_REFRESH_CRON', '*/30 * *'],
        ['CISA_KEV_REFRESH_CRON', 'none'],
        ['CISA_CSAF_REFRESH_CRON', '17 */6 * *'],
        ['CISA_CSAF_REFRESH_CRON', 'disabled'],
      ] as const) {
        resetServerConfig();
        vi.unstubAllEnvs();
        vi.stubEnv(variable, value);
        let thrown: unknown;
        try {
          getServerConfig();
        } catch (error) {
          thrown = error;
        }
        expect(thrown, `${variable}=${value}`).toBeInstanceOf(McpError);
        expect((thrown as McpError).code).toBe(JsonRpcErrorCode.ConfigurationError);
        expect((thrown as McpError).message).toContain(variable);
        expect((thrown as McpError).message).toContain('off');
      }
    });
  });
});
