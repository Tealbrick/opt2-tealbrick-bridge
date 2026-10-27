/**
 * Hook recipients (spec next, unreleased; C373, G-6; BRIDGE "hook recipients", cap `hook_recipients`): who an outward call
 * talks to, for the hook `call.target`. The places come from the op (`Operation.recipients`, pointers into the input) or, for a
 * dynamic op, from the tool's cached resolution (`DynamicResolution.recipients`, pointers into `input.arguments`); the values are
 * read from THIS call with the manifest package's `extractRecipients` (the one implementation, L1). Pure; `calls.ts` applies it
 * in `route`. The result is never logged (it is personal data like the input; the call line keeps the input digest only).
 */
import { extractRecipients, isRecipientsOutward } from "@opt2-tealbrick/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { isRecord } from "./util.ts";

export interface HookRecipients {
  recipients: string[];
  recipientsIncomplete?: true;
}

/**
 * The `target.recipients` / `target.recipientsIncomplete` members for one call, or undefined (= unknown: not outward, or no
 * places declared). `op` is the EFFECTIVE op (a dynamic op's resolution: effect and holdFamily); `places` the op's or the resolution's
 * `recipients` as read (structurally, until the spec pin types them); `dynamic` = read the places in `input.arguments`.
 * Malformed places → `{recipients: [], recipientsIncomplete: true}` (a policy fails closed; the call is not refused here).
 */
export function hookRecipients(op: { effect: string; holdFamily?: string }, places: unknown, dynamic: boolean, input: Json): HookRecipients | undefined {
  // outward = effect or holdFamily `outward` (manifest `isRecipientsOutward`, MANIFEST M-OP-14)
  if (!isRecipientsOutward(op) || places === undefined) return undefined;
  const root = dynamic ? (isRecord(input) ? input.arguments : undefined) : input;
  const r = extractRecipients(root, places);
  return { recipients: r.recipients, ...(r.incomplete ? { recipientsIncomplete: true as const } : {}) };
}
