import type { ReasoningEffort } from "../settings";
import { EXTRA_MODEL_PROVIDERS } from "./model-capabilities";

type ThinkingConfig = {
  type: "enabled" | "disabled";
};

type ThinkingRequestOptions = {
  thinking?: ThinkingConfig;
  extra_body?: {
    reasoning_effort?: ReasoningEffort;
  };
};

export function buildThinkingRequestOptions(
  thinkingEnabled: boolean,
  baseURL?: string,
  reasoningEffort: ReasoningEffort = "max"
): ThinkingRequestOptions {
  // `thinking` is DeepSeek's own extension of the OpenAI chat completions
  // schema, not part of the standard OpenAI API. Providers registered in
  // EXTRA_MODEL_PROVIDERS (e.g. Gemini's OpenAI-compat endpoint) validate the
  // request body strictly and reject this unknown field outright, failing
  // the ENTIRE request with an opaque HTTP 400 — so omit it there instead of
  // sending `{type: "disabled"}`. DeepSeek itself and any other
  // OpenAI-compatible endpoint (e.g. a Coding Plan base URL) keep getting it
  // exactly as before.
  const isExtraProvider = baseURL !== undefined && EXTRA_MODEL_PROVIDERS.some((p) => p.baseURL === baseURL);
  if (isExtraProvider) {
    return {};
  }

  const thinking: ThinkingConfig = { type: thinkingEnabled ? "enabled" : "disabled" };

  return {
    thinking,
    ...(thinkingEnabled ? { extra_body: { reasoning_effort: reasoningEffort } } : {}),
  };
}
