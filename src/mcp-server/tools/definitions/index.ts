/**
 * @fileoverview Tool barrel — every tool definition this server registers.
 * @module mcp-server/tools/definitions/index
 */

import { checkCveStatusTool } from './check-cve-status.tool.js';
import { getAdvisoryTool } from './get-advisory.tool.js';
import { getAlertsTool } from './get-alerts.tool.js';
import { getSsvcTool } from './get-ssvc.tool.js';
import { listReferenceTool } from './list-reference.tool.js';
import { searchIcsAdvisoriesTool } from './search-ics-advisories.tool.js';
import { searchKevTool } from './search-kev.tool.js';

export {
  checkCveStatusTool,
  getAdvisoryTool,
  getAlertsTool,
  getSsvcTool,
  listReferenceTool,
  searchIcsAdvisoriesTool,
  searchKevTool,
};

/** Every tool definition, in the order the catalog presents them. */
export const allToolDefinitions = [
  listReferenceTool,
  checkCveStatusTool,
  searchKevTool,
  getSsvcTool,
  searchIcsAdvisoriesTool,
  getAdvisoryTool,
  getAlertsTool,
];
