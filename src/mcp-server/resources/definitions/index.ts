/**
 * @fileoverview Resource barrel — every resource definition this server registers.
 * @module mcp-server/resources/definitions/index
 */

import { icsAdvisoryResource } from './ics-advisory.resource.js';
import { kevEntryResource } from './kev-entry.resource.js';

export { icsAdvisoryResource, kevEntryResource };

/** Every resource definition. Both are fully covered by the tool surface. */
export const allResourceDefinitions = [kevEntryResource, icsAdvisoryResource];
