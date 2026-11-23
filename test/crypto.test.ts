import { describe, expect, it } from "vitest";
import {
  DecryptError,
  FAN_CODE_MIN_LENGTH,
  KEY_BYTES,
  b64u,
  decrypt,
  dippAad,
  encrypt,
  exportPublicKey,
  fanCodeKey,
  generateKeyPair,
  newId,
  newKey,
  openSealed,
  linkParts,
  linkUrl,
  newLinkSecret,
  parseLinkFragment,
  passphraseKey,
  randomBytes,
  seal,
  utf8,
} from "../src/index";

// Low iteration counts keep key-derivation tests fast; the default is checked separately.
const FAST = 1_000;

describe("b64u", () => {
  it("round-trips every byte value and every length remainder", () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    for (const len of [0, 1, 2, 3, 4, 255, 256]) {
      const bytes = all.subarray(0, len);
      const text = b64u.encode(bytes);
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(Array.from(b64u.decode(text))).toEqual(Array.from(bytes));
    }
  });

  it("rejects characters outside the URL-safe alphabet and impossible lengths", () => {
    expect(() => b64u.decode("ab+c")).toThrow(TypeError);
    expect(() => b64u.decode("ab/c")).toThrow(TypeError);
    expect(() => b64u.decode("abcd=")).toThrow(TypeError);
    expect(() => b64u.decode("abcde")).toThrow(TypeError); // length % 4 === 1 can't be valid
  });
});

describe("ids and keys", () => {
  it("makes 22-character IDs and 32-byte keys that don't repeat", () => {
    const ids = new Set(Array.from({ length: 500 }, newId));
    expect(ids.size).toBe(500);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(newKey()).toHaveLength(KEY_BYTES);
    expect(b64u.encode(newKey())).not.toBe(b64u.encode(newKey()));
  });
});

describe("encrypt / decrypt", () => {
  const id = "AAAAAAAAAAAAAAAAAAAAAA";

  it("round-trips text, including non-ASCII", async () => {
    const key = newKey();
    const msg = "The door code is 4826. See you at 8! 🔥 café";
    const sealed = await encrypt(key, utf8.encode(msg), dippAad(id));
    expect(utf8.decode(await decrypt(key, sealed, dippAad(id)))).toBe(msg);
  });

  it("never contains the plaintext, and uses a fresh IV every time", async () => {
    const key = newKey();
    const pt = utf8.encode("secret secret secret secret");
    const a = await encrypt(key, pt, dippAad(id));
    const b = await encrypt(key, pt, dippAad(id));
    expect(b64u.encode(a)).not.toBe(b64u.encode(b));
    const hay = Array.from(a).join(",");
    expect(hay.includes(Array.from(pt).join(","))).toBe(false);
  });

  it("fails with the wrong key", async () => {
    const sealed = await encrypt(newKey(), utf8.encode("hi"), dippAad(id));
    await expect(decrypt(newKey(), sealed, dippAad(id))).rejects.toBeInstanceOf(DecryptError);
  });

  it("fails when ciphertext is moved to another link (associated data)", async () => {
    const key = newKey();
    const sealed = await encrypt(key, utf8.encode("hi"), dippAad(id));
    await expect(decrypt(key, sealed, dippAad("BBBBBBBBBBBBBBBBBBBBBB"))).rejects.toBeInstanceOf(DecryptError);
    await expect(decrypt(key, sealed, dippAad(id, "prompt"))).rejects.toBeInstanceOf(DecryptError);
  });

  it("fails when a single bit is flipped, or the data is truncated", async () => {
    const key = newKey();
    const sealed = await encrypt(key, utf8.encode("hello there"), dippAad(id));
    for (const at of [0, 12, sealed.length - 1]) {
      const tampered = sealed.slice();
      tampered[at]! ^= 1;
      await expect(decrypt(key, tampered, dippAad(id))).rejects.toBeInstanceOf(DecryptError);
    }
    await expect(decrypt(key, sealed.subarray(0, 20), dippAad(id))).rejects.toBeInstanceOf(DecryptError);
  });

  it("refuses keys of the wrong size", async () => {
    await expect(encrypt(randomBytes(16), utf8.encode("x"), dippAad(id))).rejects.toThrow(TypeError);
  });
});

describe("passphraseKey", () => {
  const salt = randomBytes(16);

  it("needs both the link key and the passphrase", async () => {
    const linkKey = newKey();
    const k = await passphraseKey(linkKey, "purple elephant", salt, FAST);
    expect(k).toHaveLength(KEY_BYTES);
    expect(b64u.encode(k)).not.toBe(b64u.encode(linkKey));
    const sealed = await encrypt(k, utf8.encode("bank details"), dippAad("x"));

    const same = await passphraseKey(linkKey, "purple elephant", salt, FAST);
    expect(utf8.decode(await decrypt(same, sealed, dippAad("x")))).toBe("bank details");

    const wrongPass = await passphraseKey(linkKey, "purple elephants", salt, FAST);
    await expect(decrypt(wrongPass, sealed, dippAad("x"))).rejects.toBeInstanceOf(DecryptError);

    const wrongLink = await passphraseKey(newKey(), "purple elephant", salt, FAST);
    await expect(decrypt(wrongLink, sealed, dippAad("x"))).rejects.toBeInstanceOf(DecryptError);
  });

  it("treats the same passphrase typed with different Unicode forms as equal", async () => {
    const linkKey = newKey();
    const composed = await passphraseKey(linkKey, "café", salt, FAST);
    const decomposed = await passphraseKey(linkKey, "café", salt, FAST);
    expect(b64u.encode(composed)).toBe(b64u.encode(decomposed));
  });

  it("uses 600,000 iterations by default", async () => {
    const linkKey = newKey();
    const byDefault = await passphraseKey(linkKey, "pw", salt);
    expect(b64u.encode(byDefault)).toBe(b64u.encode(await passphraseKey(linkKey, "pw", salt, 600_000)));
    expect(b64u.encode(byDefault)).not.toBe(b64u.encode(await passphraseKey(linkKey, "pw", salt, 599_999)));
  });
});

describe("fanCodeKey", () => {
  const salt = randomBytes(16);

  it("rejects codes shorter than the minimum, and accepts exactly the minimum", async () => {
    await expect(fanCodeKey("x".repeat(FAN_CODE_MIN_LENGTH - 1), salt, FAST)).rejects.toThrow(RangeError);
    await expect(fanCodeKey(`   ${"x".repeat(FAN_CODE_MIN_LENGTH - 1)}   `, salt, FAST)).rejects.toThrow(RangeError);
    await expect(fanCodeKey("x".repeat(FAN_CODE_MIN_LENGTH), salt, FAST)).resolves.toHaveLength(KEY_BYTES);
  });

  it("derives a different key for a different code or salt", async () => {
    const a = b64u.encode(await fanCodeKey("MAYA-FANS-2026", salt, FAST));
    expect(b64u.encode(await fanCodeKey("MAYA-FANS-2027", salt, FAST))).not.toBe(a);
    expect(b64u.encode(await fanCodeKey("MAYA-FANS-2026", randomBytes(16), FAST))).not.toBe(a);
    expect(b64u.encode(await fanCodeKey("  MAYA-FANS-2026 ", salt, FAST))).toBe(a);
  });
});

describe("seal / openSealed", () => {
  const aad = utf8.encode("dippme/card/req123/number");

  it("only the intended recipient can open a sealed item", async () => {
    const visitor = await generateKeyPair();
    const stranger = await generateKeyPair();
    const sealed = await seal(await exportPublicKey(visitor.publicKey), utf8.encode("+1 555 0100"), aad);

    expect(utf8.decode(await openSealed(visitor, sealed, aad))).toBe("+1 555 0100");
    await expect(openSealed(stranger, sealed, aad)).rejects.toBeInstanceOf(DecryptError);
  });

  it("fails for the wrong context, a swapped sender key or a tampered box", async () => {
    const visitor = await generateKeyPair();
    const pub = await exportPublicKey(visitor.publicKey);
    const sealed = await seal(pub, utf8.encode("my snap: maya.r"), aad);

    await expect(openSealed(visitor, sealed, utf8.encode("dippme/card/req123/snap"))).rejects.toBeInstanceOf(
      DecryptError,
    );
    const other = await seal(pub, utf8.encode("x"), aad);
    await expect(openSealed(visitor, { epk: other.epk, box: sealed.box }, aad)).rejects.toBeInstanceOf(DecryptError);
    await expect(openSealed(visitor, { epk: "not-a-key", box: sealed.box }, aad)).rejects.toBeInstanceOf(DecryptError);
    const box = b64u.decode(sealed.box);
    box[box.length - 1]! ^= 1;
    await expect(openSealed(visitor, { epk: sealed.epk, box: b64u.encode(box) }, aad)).rejects.toBeInstanceOf(
      DecryptError,
    );
  });

  it("uses a fresh one-off key for every seal", async () => {
    const visitor = await generateKeyPair();
    const pub = await exportPublicKey(visitor.publicKey);
    const a = await seal(pub, utf8.encode("same"), aad);
    const b = await seal(pub, utf8.encode("same"), aad);
    expect(a.epk).not.toBe(b.epk);
    expect(a.box).not.toBe(b.box);
  });

  it("keeps private keys non-extractable", async () => {
    const pair = await generateKeyPair();
    expect(pair.privateKey.extractable).toBe(false);
    await expect(globalThis.crypto.subtle.exportKey("pkcs8", pair.privateKey)).rejects.toThrow();
  });

  it("rejects a malformed recipient key", async () => {
    await expect(seal("abc", utf8.encode("x"), aad)).rejects.toThrow(TypeError);
  });
});

describe("links", () => {
  it("are short: one 22-character secret after the #", () => {
    const url = linkUrl("https://dipp.chat/", "dipp", newLinkSecret());
    expect(url).toMatch(/^https:\/\/dipp\.chat\/l#[A-Za-z0-9_-]{22}$/);
    expect(url.replace("https://", "").length).toBe(34); // dipp.chat/l#…, as people see it
    expect(linkUrl("https://dipp.chat", "room", newLinkSecret(), true)).toMatch(/^https:\/\/dipp\.chat\/r#[A-Za-z0-9_-]{22}\.p$/);
  });

  it("parse back to the same secret, and the passphrase marker survives", () => {
    const secret = newLinkSecret();
    const parsed = parseLinkFragment(new URL(linkUrl("https://dipp.chat", "dipp", secret, true)).hash);
    expect(parsed && b64u.encode(parsed.secret)).toBe(b64u.encode(secret));
    expect(parsed?.passphrase).toBe(true);
    expect(parseLinkFragment(new URL(linkUrl("https://dipp.chat", "dipp", secret)).hash)?.passphrase).toBe(false);
  });

  it("derive the same ID and key every time, and a different pair for a different secret or kind", async () => {
    const secret = newLinkSecret();
    const a = await linkParts("dipp", secret);
    const b = await linkParts("dipp", secret);
    expect(a.id).toBe(b.id);
    expect(a.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(b64u.encode(a.key)).toBe(b64u.encode(b.key));
    expect(a.key).toHaveLength(KEY_BYTES);
    const room = await linkParts("room", secret);
    expect(room.id).not.toBe(a.id);
    expect(b64u.encode(room.key)).not.toBe(b64u.encode(a.key));
    const other = await linkParts("dipp", newLinkSecret());
    expect(other.id).not.toBe(a.id);
  });

  it("never put the secret itself in the ID the server sees", async () => {
    const secret = newLinkSecret();
    const { id, key } = await linkParts("dipp", secret);
    expect(id).not.toBe(b64u.encode(secret));
    expect(b64u.encode(key)).not.toContain(b64u.encode(secret));
  });

  it("refuse fragments that aren't exactly a 16-byte secret", async () => {
    const good = b64u.encode(newLinkSecret());
    expect(parseLinkFragment(good)).not.toBeNull();
    expect(parseLinkFragment(good.slice(1))).toBeNull();
    expect(parseLinkFragment(`${good}x`)).toBeNull();
    expect(parseLinkFragment(`${good}.q`)).toBeNull();
    expect(parseLinkFragment("")).toBeNull();
    expect(parseLinkFragment(b64u.encode(newKey()))).toBeNull(); // an old-style 43-character key
    await expect(linkParts("dipp", randomBytes(15))).rejects.toThrow(TypeError);
  });
});

describe("moments, mutual yes, asks and shots", () => {
  it("every kind gets its own path letter and its own ID from the same secret", async () => {
    const { linkParts: parts, linkUrl: url, newLinkSecret: fresh } = await import("../src/index");
    const secret = fresh();
    expect(url("https://dipp.chat", "moment", secret)).toMatch(/^https:\/\/dipp\.chat\/m#/);
    expect(url("https://dipp.chat", "yes", secret)).toMatch(/\/y#/);
    expect(url("https://dipp.chat", "ask", secret)).toMatch(/\/a#/);
    expect(url("https://dipp.chat", "shot", secret)).toMatch(/\/s#/);
    const ids = await Promise.all((["dipp", "room", "moment", "yes", "ask", "shot"] as const).map(async (k) => (await parts(k, secret)).id));
    expect(new Set(ids).size).toBe(6);
  });

  it("a part opens only under the same kind, ID and part name", async () => {
    const { sealPart, openPart, newKey: key } = await import("../src/index");
    const k = key();
    const sealed = await sealPart(k, "moment", "id1", "photo:a", new Uint8Array([1, 2, 3]));
    expect([...(await openPart(k, "moment", "id1", "photo:a", sealed))]).toEqual([1, 2, 3]);
    await expect(openPart(k, "moment", "id1", "photo:b", sealed)).rejects.toThrow();
    await expect(openPart(k, "moment", "id2", "photo:a", sealed)).rejects.toThrow();
    await expect(openPart(k, "ask", "id1", "photo:a", sealed)).rejects.toThrow();
  });

  it("two yeses under the same link are equal; a no never equals a yes; another link's yes differs", async () => {
    const { yesAnswer, newKey: key } = await import("../src/index");
    const k = key();
    const yes = await yesAnswer(k, "id1", true);
    expect(yes).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await yesAnswer(k, "id1", true)).toBe(yes);
    const no = await yesAnswer(k, "id1", false);
    expect(no).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(no).not.toBe(yes);
    expect(await yesAnswer(k, "id1", false)).not.toBe(no);
    expect(await yesAnswer(k, "id2", true)).not.toBe(yes);
    expect(await yesAnswer(key(), "id1", true)).not.toBe(yes);
  });
});
