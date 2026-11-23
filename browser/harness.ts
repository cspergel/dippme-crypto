/**
 * Loaded into real browser engines (Chromium, WebKit, Firefox) by crypto.browser.spec.ts.
 * Exposes the crypto package on window so the test can pass data between engines.
 */
import * as c from "../src/index";

const pairs = new Map<string, CryptoKeyPair>();
const enc = (s: string) => c.utf8.encode(s);

async function rejects(fn: () => Promise<unknown>, name: string): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch (e) {
    return (e as Error).name === name;
  }
}

/** Checks that run inside one engine. Returns the names of any that failed. */
async function selfTest(): Promise<string[]> {
  const failures: string[] = [];
  const check = async (name: string, fn: () => Promise<boolean>) => {
    try {
      if (!(await fn())) failures.push(name);
    } catch (e) {
      failures.push(`${name}: ${(e as Error).message}`);
    }
  };
  const id = c.newId();
  const key = c.newKey();

  await check("secure context", async () => globalThis.isSecureContext === true);
  await check("round trip", async () => {
    const sealed = await c.encrypt(key, enc("Door code 4826 🔥 café"), c.dippAad(id));
    return c.utf8.decode(await c.decrypt(key, sealed, c.dippAad(id))) === "Door code 4826 🔥 café";
  });
  await check("wrong key fails", async () => {
    const sealed = await c.encrypt(key, enc("x"), c.dippAad(id));
    return rejects(() => c.decrypt(c.newKey(), sealed, c.dippAad(id)), "DecryptError");
  });
  await check("moved ciphertext fails", async () => {
    const sealed = await c.encrypt(key, enc("x"), c.dippAad(id));
    return rejects(() => c.decrypt(key, sealed, c.dippAad(c.newId())), "DecryptError");
  });
  await check("tampered ciphertext fails", async () => {
    const sealed = await c.encrypt(key, enc("hello"), c.dippAad(id));
    sealed[sealed.length - 1]! ^= 1;
    return rejects(() => c.decrypt(key, sealed, c.dippAad(id)), "DecryptError");
  });
  await check("short link build, parse and derive", async () => {
    const secret = c.newLinkSecret();
    const url = new URL(c.linkUrl("https://dipp.chat", "dipp", secret, true));
    const parsed = c.parseLinkFragment(url.hash);
    if (!parsed || !parsed.passphrase) return false;
    const a = await c.linkParts("dipp", parsed.secret);
    const b = await c.linkParts("dipp", secret);
    return a.id === b.id && c.b64u.encode(a.key) === c.b64u.encode(b.key);
  });
  await check("private keys can't be exported", async () => {
    const pair = await c.generateKeyPair();
    try {
      await crypto.subtle.exportKey("pkcs8", pair.privateKey);
      return false;
    } catch {
      return pair.privateKey.extractable === false;
    }
  });
  await check("seal and open", async () => {
    const pair = await c.generateKeyPair();
    const sealed = await c.seal(await c.exportPublicKey(pair.publicKey), enc("+1 555 0100"), enc("ctx"));
    const stranger = await c.generateKeyPair();
    return (
      c.utf8.decode(await c.openSealed(pair, sealed, enc("ctx"))) === "+1 555 0100" &&
      (await rejects(() => c.openSealed(stranger, sealed, enc("ctx")), "DecryptError"))
    );
  });
  await check("passphrase Unicode forms match", async () => {
    const salt = c.randomBytes(16);
    const a = await c.passphraseKey(key, "café", salt, 1_000);
    const b = await c.passphraseKey(key, "café", salt, 1_000);
    return c.b64u.encode(a) === c.b64u.encode(b);
  });
  return failures;
}

const api = {
  selfTest,
  info: () => ({ secure: globalThis.isSecureContext, ua: navigator.userAgent }),
  newKey: () => c.b64u.encode(c.newKey()),
  newId: () => c.newId(),
  async encryptText(key: string, text: string, id: string) {
    return c.b64u.encode(await c.encrypt(c.b64u.decode(key), enc(text), c.dippAad(id)));
  },
  async decryptText(key: string, ciphertext: string, id: string) {
    return c.utf8.decode(await c.decrypt(c.b64u.decode(key), c.b64u.decode(ciphertext), c.dippAad(id)));
  },
  async makePair(name: string) {
    const pair = await c.generateKeyPair();
    pairs.set(name, pair);
    return c.exportPublicKey(pair.publicKey);
  },
  sealTo: (pub: string, text: string, aad: string) => c.seal(pub, enc(text), enc(aad)),
  async open(name: string, sealed: c.Sealed, aad: string) {
    return c.utf8.decode(await c.openSealed(pairs.get(name)!, sealed, enc(aad)));
  },
  async linkId(secret: string) {
    return (await c.linkParts("dipp", c.b64u.decode(secret))).id;
  },
  async passKey(linkKey: string, passphrase: string, salt: string, iterations?: number) {
    return c.b64u.encode(await c.passphraseKey(c.b64u.decode(linkKey), passphrase, c.b64u.decode(salt), iterations));
  },
  async fanKey(code: string, salt: string, iterations?: number) {
    return c.b64u.encode(await c.fanCodeKey(code, c.b64u.decode(salt), iterations));
  },
};

export type Harness = typeof api;
(globalThis as unknown as { dipp: Harness }).dipp = api;
