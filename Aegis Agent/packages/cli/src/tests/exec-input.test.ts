import { test } from "node:test";
import assert from "node:assert/strict";
import { buildExecPrompt, type ExecInputStream } from "../exec-input";

function inputFrom(chunks: Array<string | Uint8Array>, isTTY = false): ExecInputStream {
  return {
    isTTY,
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk;
    },
  };
}

test("buildExecPrompt does not read TTY stdin", async () => {
  let iterated = false;
  const input: ExecInputStream = {
    isTTY: true,
    async *[Symbol.asyncIterator]() {
      iterated = true;
      yield "ignored";
    },
  };
  assert.equal(await buildExecPrompt("task", input), "task");
  assert.equal(iterated, false);
});

test("buildExecPrompt ignores empty and whitespace-only redirected stdin", async () => {
  for (const content of ["", "  \n\t"]) {
    assert.equal(await buildExecPrompt("task", inputFrom([content])), "task");
  }
});

test("buildExecPrompt appends stdin without a trailing newline", async () => {
  assert.equal(await buildExecPrompt("task", inputFrom(["line one"])), "task\n\n<stdin>\nline one\n</stdin>");
});

test("buildExecPrompt preserves an existing trailing newline", async () => {
  assert.equal(await buildExecPrompt("task", inputFrom(["line one\n"])), "task\n\n<stdin>\nline one\n</stdin>");
});

test("buildExecPrompt preserves multiline stdin across chunks", async () => {
  assert.equal(
    await buildExecPrompt("task", inputFrom([Buffer.from("one\n"), Buffer.from("two")])),
    "task\n\n<stdin>\none\ntwo\n</stdin>"
  );
});

test("buildExecPrompt reports stdin read failures", async () => {
  const input: ExecInputStream = {
    isTTY: false,
    [Symbol.asyncIterator]() {
      return {
        next: async () => {
          throw new Error("broken pipe");
        },
      };
    },
  };
  await assert.rejects(() => buildExecPrompt("task", input), /Failed to read stdin: broken pipe/);
});

test("buildExecPrompt rejects invalid UTF-8", async () => {
  await assert.rejects(
    () => buildExecPrompt("task", inputFrom([Buffer.from([0xc3, 0x28])])),
    /Failed to decode stdin as UTF-8/
  );
});
