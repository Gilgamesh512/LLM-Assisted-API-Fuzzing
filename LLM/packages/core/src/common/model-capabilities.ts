export const DEEPSEEK_V4_MODELS = new Set(["deepseek-v4-flash", "deepseek-v4-pro"]);

export const NON_MULTIMODAL_MODELS = new Set([
  "deepseek-v4-pro",
  "deepseek-v4-flash",
  "deepseek-chat",
  "deepseek-reasoner",
]);

export type MultimodalMode = "default" | "on" | "off";

export function defaultsToThinkingMode(model: string): boolean {
  return DEEPSEEK_V4_MODELS.has(model);
}

/**
 * Whether the given model supports multimodal (image) content.
 *
 * `mode` is the resolved `multimodal` configuration:
 * - `"on"`: always treat the model as multimodal.
 * - `"off"`: always treat the model as non-multimodal.
 * - `"default"` (or omitted): infer from the known model list.
 */
export function supportsMultimodal(model: string, mode: MultimodalMode = "default"): boolean {
  if (mode === "on") {
    return true;
  }
  if (mode === "off") {
    return false;
  }
  return !NON_MULTIMODAL_MODELS.has(model.trim());
}

/**
 * A selectable model that lives on a DIFFERENT provider/endpoint than the
 * built-in DeepSeek models (different `baseURL`, different API key).
 *
 * DeepSeek-to-DeepSeek model switches (`deepseek-v4-pro` <-> `deepseek-v4-flash`)
 * never touch `env.BASE_URL`/`env.API_KEY` — see `applyModelConfigSelection` in
 * `settings.ts`. Only switching into or out of one of these "extra" providers
 * does, so users who point `BASE_URL` at a custom OpenAI-compatible endpoint
 * (e.g. a Coding Plan) while still using a `deepseek-*` model name keep that
 * override intact.
 *
 * `apiKeyEnv` is the `env.<KEY>` field this provider's API key is persisted
 * under (separate from the currently-active `env.API_KEY`) so switching back
 * and forth doesn't lose either key — see `scripts/switch_ai.py` in the
 * `Aegis Agent` research-project checkout, which seeds both from `.env`.
 */
export interface ExtraModelProvider {
  model: string;
  label: string;
  baseURL: string;
  apiKeyEnv: string;
  defaultThinkingEnabled: boolean;
}

export const EXTRA_MODEL_PROVIDERS: ExtraModelProvider[] = [
  {
    model: "gemini-2.5-flash",
    label: "Gemini 2.5 Flash (free tier, via OpenAI-compat endpoint)",
    baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/",
    apiKeyEnv: "GEMINI_API_KEY",
    defaultThinkingEnabled: false,
  },
];

export function findExtraModelProvider(model: string): ExtraModelProvider | undefined {
  return EXTRA_MODEL_PROVIDERS.find((provider) => provider.model === model.trim());
}
