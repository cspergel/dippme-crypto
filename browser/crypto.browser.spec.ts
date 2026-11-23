import { chromium, expect, firefox, test, webkit, type Browser, type Page } from "@playwright/test";
import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";
import type { Harness } from "./harness";

/**
 * Runs @dippme/crypto in Chromium (Chrome, Edge, Android), WebKit (Safari, every iPhone browser) and
 * Firefox, and passes data between them: a value sealed in one engine must open in another, and key
 * derivation must give the same bytes everywhere.
 */

const ORIGIN = "https://check.dippme.test"; // https, so Web Crypto runs in a secure context
const harness = buildSync({
  entryPoints: [fileURLToPath(new URL("./harness.ts", import.meta.url))],
  bundle: true,
  format: "iife",
  target: "es2020",
  write: false,
}).outputFiles[0]!.text;

const engines = { chromium, webkit, firefox } as const;
type Engine = keyof typeof engines;
const names = Object.keys(engines) as Engine[];

const browsers: Partial<Record<Engine, Browser>> = {};
const pages: Partial<Record<Engine, Page>> = {};

test.beforeAll(async () => {
  for (const name of names) {
    const browser = await engines[name].launch();
    const page = await browser.newPage();
    await page.route(`${ORIGIN}/**`, (route) =>
      route.fulfill({ contentType: "text/html", body: `<!doctype html><script>${harness}</script>` }),
    );
    await page.goto(`${ORIGIN}/`);
    browsers[name] = browser;
    pages[name] = page;
  }
});

test.afterAll(async () => {
  await Promise.all(Object.values(browsers).map((b) => b?.close()));
});

/** Calls a harness function inside one engine. */
function run<K extends keyof Harness>(engine: Engine, fn: K, ...args: Parameters<Harness[K]>) {
  return pages[engine]!.evaluate(
    ([f, a]) => (globalThis as unknown as { dipp: Record<string, (...x: unknown[]) => unknown> }).dipp[f]!(...a),
    [fn, args] as [string, unknown[]],
  ) as Promise<Awaited<ReturnType<Harness[K]>>>;
}

for (const name of names) {
  test(`every check passes in ${name}`, async () => {
    expect((await run(name, "info")).secure).toBe(true);
    expect(await run(name, "selfTest")).toEqual([]);
  });
}

for (const from of names) {
  for (const to of names) {
    if (from === to) continue;

    test(`a Dipp encrypted in ${from} opens in ${to}`, async () => {
      const key = await run(from, "newKey");
      const id = await run(from, "newId");
      const ct = await run(from, "encryptText", key, "The door code is 4826. See you at 8! 🔥", id);
      expect(await run(to, "decryptText", key, ct, id)).toBe("The door code is 4826. See you at 8! 🔥");
    });

    test(`a card item sealed in ${from} opens only in the ${to} visitor's browser`, async () => {
      const pub = await run(to, "makePair", "visitor");
      const sealed = await run(from, "sealTo", pub, "+1 555 0100", "dippme/card/req/number");
      expect(await run(to, "open", "visitor", sealed, "dippme/card/req/number")).toBe("+1 555 0100");
      await run(from, "makePair", "visitor"); // a different key pair under the same name, in the sender
      await expect(run(from, "open", "visitor", sealed, "dippme/card/req/number")).rejects.toThrow();
    });
  }
}

test("passphrase and fan-code keys come out identical in every engine, at full strength", async () => {
  const linkKey = await run("chromium", "newKey");
  const salt = "AAECAwQFBgcICQoLDA0ODw";
  const pass = await Promise.all(names.map((n) => run(n, "passKey", linkKey, "purple elephant", salt)));
  expect(new Set(pass).size).toBe(1);
  const fan = await Promise.all(names.map((n) => run(n, "fanKey", "MAYA-FANS-2026", salt)));
  expect(new Set(fan).size).toBe(1);
  expect(fan[0]).not.toBe(pass[0]);
});

test("a short link derives the same ID in every engine, so a link made on one phone opens on any other", async () => {
  const secret = "AAECAwQFBgcICQoLDA0ODw";
  const ids = await Promise.all(names.map((n) => run(n, "linkId", secret)));
  expect(new Set(ids).size).toBe(1);
  expect(ids[0]).toMatch(/^[A-Za-z0-9_-]{22}$/);
});
