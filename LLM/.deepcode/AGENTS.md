# Repository Guidelines

## Project Structure & Module Organization

This is an **npm workspaces monorepo**. Packages live under `packages/`.

```
packages/
├── core/src/               # LLM session, tool execution, shared utilities
│   ├── common/             # File I/O, permissions, telemetry, OpenAI client, shell utils, etc.
│   ├── tools/              # 9 built-in handlers (bash, read, write, edit, skill, web-search, ask-user-question, update-plan, understand-image)
│   ├── mcp/                # MCP client & manager (JSON-RPC lifecycle)
│   ├── session.ts          # SessionManager — LLM loop, compaction, tool orchestration
│   ├── prompt.ts           # System prompt builder & tool definitions
│   └── settings.ts         # Settings resolution from ~/.deepcode/settings.json
├── cli/src/                # Terminal UI (Ink/React)
│   ├── cli.tsx             # Entry point — renders AppContainer
│   ├── cli-args.ts         # CLI argument parsing (yargs: -p, -r, -v, -h)
│   ├── common/             # Update checker
│   ├── utils/              # stdio helpers, version, package info
│   ├── generated/          # Build-time git commit info
│   ├── ui/views/           # Top-level screens (App, PromptInput, SessionList, PermissionPrompt, WelcomeScreen, UpdatePrompt, McpStatusList, etc.)
│   ├── ui/components/      # Reusable Ink components (MessageView, DropdownMenu, ModelsDropdown, etc.)
│   ├── ui/core/            # Prompt buffer, slash commands, file mentions, clipboard, undo/redo
│   ├── ui/hooks/           # Custom hooks (cursor, history navigation, paste handling, terminal input, statusline)
│   ├── ui/contexts/        # React contexts (AppContext, RawModeContext)
│   ├── ui/statusline/      # Pluggable statusline providers (command, module)
│   ├── ui/utils/            # Shared UI utilities (writing, formatting)
│   └── tests/              # UI-focused tests with run-tests.mjs runner
├── vscode-ide-companion/   # VSCode extension companion
│   └── src/                # extension.ts, provider.ts, utils.ts
docs/                       # User-facing documentation (configuration, MCP, notify, permissions)
scripts/                    # Build, release, and packaging scripts
dist/                       # Bundled CLI output — single-file dist/cli.js (gitignored)
dist/bundled/               # Bundled skills & references shipped with the CLI
```

Templates for tool descriptions and prompts are at `packages/cli/dist/templates/` (copied during build from `packages/core/templates/`). Built-in skills are under `packages/cli/dist/bundled/`.

## Build, Test, and Development Commands

All commands run from the repo root.

| Command | What it does |
|---|---|
| `npm run typecheck` | TypeScript type checking across all workspaces |
| `npm run lint` | ESLint across `packages/*/src/**/*.{ts,tsx}` + `scripts/*.js` |
| `npm run lint:fix` | ESLint with auto-fix |
| `npm run format` | Prettier on all source files |
| `npm run format:check` | Prettier in check-only mode |
| `npm run check` | Runs typecheck + lint + format:check together |
| `npm run build` | Orchestrates full build (scripts/build.js) — compiles core + bundles CLI + copies assets |
| `npm run bundle` | Generates git commit info + esbuild bundle + copies bundled assets |
| `npm run build:vscode` | Builds the VSCode extension companion |
| `npm test` | Runs all workspace tests (`npm run test --workspaces --if-present`) |
| `npm run start` | Runs the locally built CLI (`scripts/start.js`) |
| `npm run build-and-start` | Builds then starts the CLI |
| `npm run clean` | Removes generated files and dist directories |
| `npm run release:version` | Bumps version across all packages |
| `npm run prepare:package` | Prepares the CLI package for distribution |
| `npm run prepare:vscode` | Prepares the VSCode extension for distribution |

To run a **single test file** within a package:
```
node packages/core/src/tests/run-tests.mjs packages/core/src/tests/session.test.ts
node packages/cli/src/tests/run-tests.mjs packages/cli/src/tests/slash-commands.test.ts
```

Run the CLI locally for manual testing: `node packages/cli/dist/cli.js` (after `npm run bundle`).

## Coding Style & Naming Conventions

- **Indentation**: 2 spaces, no tabs
- **Quotes**: Double quotes (`"`)
- **Semicolons**: Required
- **Trailing commas**: `es5` (objects, arrays, etc.)
- **Line width**: 120 characters max
- **Line endings**: LF only

**TypeScript**: Strict mode enabled (`strict: true`). Use `import type` for type-only imports (`@typescript-eslint/consistent-type-imports`). Unused variables prefixed with `_` are allowed (`argsIgnorePattern: "^_"`). Target ES2022, module ESNext with bundler resolution. JSX is `react-jsx`.

**Formatting/Linting**: Prettier (double quotes, 2-space indent, semicolons) + ESLint (typescript-eslint, react-hooks). Run `npm run check` before pushing. On commit, Husky + lint-staged auto-formats staged `*.{ts,tsx,js,mjs,cjs,jsx}` and `*.json` files.

**File naming**: `kebab-case.ts` for modules, `kebab-case.tsx` for React/Ink components. Test files: `*.test.ts` (always kebab-case).

## Testing Guidelines

- **Framework**: Node.js native test runner (`node:test`) with `tsx` for TypeScript
- **Assertions**: `node:assert/strict`
- **Coverage**: Target meaningful unit tests for core logic (session management, tool handlers, settings resolution, prompt buffer, permissions, MCP client, telemetry). Test files are in `packages/*/src/tests/` matching the source module name.
- **Test naming**: `describe`/`test` blocks with descriptive names. Example: `test("SessionManager preserves structured system content when building OpenAI messages", ...)`
- **Relaxed lint rules**: Test files allow `any` and unused vars.
- Run all tests with `npm test` before submitting a PR. Each package has its own `run-tests.mjs` cross-platform runner.

## Commit & Pull Request Guidelines

**Commit messages** follow conventional commits:

- `feat:` — new feature (e.g., `feat: add /model command`)
- `fix:` — bug fix (e.g., `fix(mcp): fix Windows MCP spawn double-quoting`)
- `chore:` — tooling, deps, hooks (e.g., `chore: add husky + lint-staged`)
- `refactor:` — code restructuring (e.g., `refactor(ui): optimize App hooks`)
- `style:` — formatting-only changes
- `test:` — adding or updating tests
- `docs:` — documentation changes
- `perf:` — performance improvements
- `build:` — build system changes

**Pull requests** should include:
- A clear description of what changed and why
- Link to related issue(s) if applicable
- Screenshots or terminal recordings for UI changes
- All checks passing (`npm run check && npm test`)
- No unintended changes to `dist/` or `package-lock.json` without justification

## Architecture Overview

The CLI (`@vegamo/deepcode-cli`) renders a terminal UI using [Ink](https://github.com/vadimdemedes/ink) (React for terminals). `SessionManager` (in `@vegamo/deepcode-core`) drives the LLM interaction loop: it builds system prompts, sends user messages with optional skills/images, streams responses, executes tool calls via `ToolExecutor`, and compacts context when token thresholds are exceeded (configurable via the `contextWindow` and `autoCompactWindow` settings). OpenAI client connectivity is managed by `createOpenAIClient()` with a 180-second keep-alive timeout; `resolveOpenAIConnection()` falls back to the DeepCode Plus endpoint when no API key is set but a DeepCode Plus key is available. API errors are normalized through `describeLlmError()` in `packages/core/src/common/llm-error.ts`, which produces credential-safe, structured error details. Image support is inferred per model by `supportsMultimodal()` in `packages/core/src/common/model-capabilities.ts`; the `multimodal` setting (`"default"`, `"on"`, or `"off"`, also settable via `MULTIMODAL` env) overrides that inference.

Nine built-in tools are available to the LLM: `bash`, `read`, `write`, `edit`, `skill`, `AskUserQuestion`, `UpdatePlan`, `UnderstandImage`, and `WebSearch`. The `skill` tool loads full instructions for a skill listed in the session skill catalog. `UnderstandImage` and `WebSearch` are plugin-backed and normalize rate-limit responses; `WebSearch` is driven by the DeepSeek Responses API. The `read` tool returns a `snippet_id` that must be passed to subsequent `edit` calls, ensuring edits always operate on a known, session-local file snapshot. Tool definitions are registered in `packages/core/src/tools/executor.ts` and described to the LLM via `packages/core/src/prompt.ts`.

A **permission system** (`packages/core/src/common/permissions.ts`) controls tool execution scopes (read/write/delete/network/git-log, etc.) with configurable allow/deny/ask decisions.

A **file history system** (`packages/core/src/common/file-history.ts`) provides undo/checkpoint support via lightweight Git branches.

**Slash commands**: `/skills`, `/model`, `/plan`, `/new`, `/init`, `/resume`, `/fork`, `/continue`, `/undo`, `/mcp`, `/raw`, `/exit`, plus dynamic `/skill-name` for each loaded skill.

**Plan Mode** (`/plan` or `Shift+Tab`): Restricts the agent to read-only operations on the first turn and requires it to produce a task plan via `<proposed_plan>` for user approval before any file writes, deletions, or git mutations. When enabled, write/delete/mutate-git-log permissions are force-asked regardless of user settings.

**Key UI features**: `@` file mentions in the prompt input, `Ctrl+O` to view live process stdout, `Ctrl+V` to paste images, `Ctrl+X` to clear images, Shift+Enter for newlines, `Shift+Tab` to toggle Plan Mode, pluggable statusline, MCP server status display, undo selector, and permission prompts.

**CLI flags**: `-p <prompt>` / `--prompt` to auto-submit a prompt on launch, `-x` / `--exec` to run a prompt non-interactively, `-r [sessionId]` / `--resume [sessionId]` to resume a session or show the session picker, `-f [sessionId]` / `--fork` to fork a session, `-l` / `--last` to resume the most recent session, `-v` / `--version`, `-h` / `--help`.

## Agent-Specific Instructions

- **AGENTS.md loading**: The CLI loads agent instructions from `./AGENTS.md`, `./.deepcode/AGENTS.md`, or `~/.deepcode/AGENTS.md` (first found wins).
- **Skills**: Place skill definitions in `~/.agents/skills/<name>/SKILL.md` (user-level) or `./.agents/skills/<name>/SKILL.md` (project-level); the legacy path `./.deepcode/skills/` is also scanned. Each SKILL.md uses YAML frontmatter with `name` and `description` fields. The session catalog contains skill summaries only — call the `skill` tool with the exact skill name to load full instructions before acting. Disable skills by name via the `enabledSkills` setting.
- **Built-in skills**: Five bundled skills ship with this fork's CLI — `deepcode-self-refer` (Deep Code CLI documentation), `image-generator` (text-to-image generation & editing), `skill-digester` (digest & install skills), `skill-writer` (create & debug skills), `api-payload-generator` (custom — see below).
- **Prompt file references**: Use `@path/to/file` syntax in prompts to load file contents through the read tool.

## Fork Customization (research project)

This checkout is customized for the NCKH research project *"Ứng dụng LLM trong
sinh tự động test case kiểm thử bảo mật API REST"* (Task B: parse OpenAPI →
LLM-generated context-aware payloads → validated JSON output). Two additions
on top of upstream `lessweb/deepcode-cli`:

1. **`packages/core/templates/skills/bundled/api-payload-generator/SKILL.md`**
  — bundled skill that makes `deepcode` act as a security test engineer,
  turning a compact endpoint JSON (produced by the workspace-level
  `../core/analyzer.py`)
   into structured attack-payload JSON (SQLi/BOLA/SSRF/JWT/FileUpload test
   cases) for OWASP crAPI/DVGA/VAmPI benchmark apps. Manual-invoke only
   (`allow-implicit-invocation: false`) so it never fires in unrelated projects.
2. **Workspace-level pipeline** (the parent workspace beside `Aegis Agent`) —
  the actual Task B project: `../core/analyzer.py` (OpenAPI → compact JSON),
  `../core/validator.py` (Pydantic guardrails matching the skill's output
  schema exactly), tests, and usage docs. Its operating rules are in the
  workspace-level `AGENTS.md`.
3. **Gemini as a second selectable model** (`/model` command), used to test
   the pipeline for free before a DeepSeek key is purchased:
   - `packages/core/src/common/model-capabilities.ts` — `EXTRA_MODEL_PROVIDERS`
     registry (currently: `gemini-2.5-flash` via Google's OpenAI-compat
     endpoint). Add a 4th provider here, nowhere else, to extend further.
   - `packages/core/src/settings.ts` — `applyModelConfigSelection` now swaps
     `env.BASE_URL`/`env.API_KEY` when the selected model crosses into/out of
     an `EXTRA_MODEL_PROVIDERS` entry, restoring each provider's key from its
     own `env.<PROVIDER>_API_KEY` field. DeepSeek-to-DeepSeek switches are
     completely untouched (verified with a dedicated test) so a custom
     `BASE_URL` (e.g. a Coding Plan endpoint) used with a `deepseek-*` model
     name is never clobbered.
   - `packages/core/src/common/openai-thinking.ts` — `buildThinkingRequestOptions`
     omits the DeepSeek-only `thinking` request field for `EXTRA_MODEL_PROVIDERS`
     endpoints. Without this, every request to Gemini's OpenAI-compat endpoint
     failed with an opaque `HTTP 400: 400 status code (no body)` — Gemini's
     compat layer rejects the unrecognized field outright. Diagnosed via
     `debugLogEnabled: true` → `~/.deepcode/logs/debug.log`.
   - `packages/cli/src/ui/components/ModelsDropdown/index.tsx` — `/model`
     dropdown lists `EXTRA_MODEL_PROVIDERS` models alongside the two DeepSeek
     ones.
   - `../scripts/switch_ai.py` — companion CLI switcher; also
     seeds every provider's key (from the workspace `.env`) into
     `~/.deepcode/settings.json` as `env.<PROVIDER>_API_KEY` so the native
     `/model` picker has both keys available regardless of which one was used
     to switch last.
  - Verified end-to-end: `deepcode -x -p "..."` invoking the
    `api-payload-generator` skill against Gemini produced 8 valid
    `AttackPayload` JSON objects, 100% passing `../core/validator.py`. See
    `../docs/end_to_end_pipeline_test_2026-08-22.md`.

**After editing the skill**, rebuild so `dist/bundled/` picks up the change:
`npm run build` (root) — the global `deepcode` command is `npm link`ed to
`packages/cli`, so a rebuild here is immediately live everywhere, no reinstall
needed. Keep the skill's documented output schema (method/path/
target_parameter/location/vulnerability_type/payload_value/rationale/
expected_indicator) in sync with `AttackPayload` in
`../core/validator.py` — the two must never drift apart.
