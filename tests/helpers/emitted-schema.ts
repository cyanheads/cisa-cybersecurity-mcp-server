/**
 * @fileoverview The JSON Schema a tool's `structuredContent` is judged against
 * on the client side, and a validator built from that JSON text alone.
 *
 * The schema is emitted the way the MCP SDK emits a tool's `outputSchema` for
 * `tools/list` — `~standard.jsonSchema.output({ target: 'draft-2020-12' })` over
 * the success shape, `output` extended with the declared `enrichment` block. The
 * advertised schema additionally makes each top-level field optional and adds
 * an `error` branch; every nested property schema, `pattern` included, is the
 * same node. The validator is rebuilt from the JSON with `z.fromJSONSchema`,
 * which compiles each `pattern` as `new RegExp(pattern)` — no flags, exactly as
 * a strict client's validator reads it. A Zod-side regex flag never survives the
 * trip, which is the point.
 * @module tests/helpers/emitted-schema
 */

import { z } from '@cyanheads/mcp-ts-core';

interface SchemaCarrier {
  enrichment?: Record<string, z.ZodType> | undefined;
  output: z.ZodObject;
}

/** The emitted success-shape output JSON Schema for a tool definition. */
export function emittedOutputSchema(definition: SchemaCarrier): Record<string, unknown> {
  const success = definition.enrichment
    ? definition.output.extend(definition.enrichment)
    : definition.output;
  const standard = success['~standard'] as unknown as {
    jsonSchema: { output: (options: { target: string }) => Record<string, unknown> };
  };
  return standard.jsonSchema.output({ target: 'draft-2020-12' });
}

/** A validator built from the emitted JSON Schema text alone — the client's view. */
export function strictClientValidator(definition: SchemaCarrier): z.ZodType {
  return z.fromJSONSchema(
    emittedOutputSchema(definition) as Parameters<typeof z.fromJSONSchema>[0],
  );
}
