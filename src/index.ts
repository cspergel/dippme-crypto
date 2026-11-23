/**
 * @dippme/crypto: every key DippMe makes, and everything it encrypts.
 *
 * Web Crypto only (browsers, Cloudflare Workers, Node 20+, and the phone through a Web Crypto polyfill).
 * Rules: keys are made on a device, and travel only after the # in a link or sealed to a public key.
 * Nothing in here logs, and nothing in here talks to the network.
 */

const subtle = crypto.subtle;

/** Thrown when decryption fails: wrong key, wrong link, or tampered data. Never says which. */
export class DecryptError extends Error {
  constructor() {
    super("Could not decrypt");
    this.name = "DecryptError";
  }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export const b64u = {
  encode(bytes: Uint8Array): string {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(text: string): Uint8Array {
    if (!B64U_RE.test(text) || text.length % 4 === 1) throw new TypeError("Invalid base64url");
    const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export const utf8 = {
  encode: (text: string): Uint8Array => encoder.encode(text),
  decode: (bytes: Uint8Array): string => decoder.decode(bytes),
};

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Copies into a fresh ArrayBuffer-backed view, which Web Crypto's types require. */
function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}

// ---------------------------------------------------------------------------
// Random values
// ---------------------------------------------------------------------------

export const KEY_BYTES = 32;
export const ID_BYTES = 16;
const IV_BYTES = 12;

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/** A new random ID for a Dipp, room or tag: 16 bytes, 22 base64url characters. */
export function newId(): string {
  return b64u.encode(randomBytes(ID_BYTES));
}

/** A new random 256-bit symmetric key. */
export function newKey(): Uint8Array {
  return randomBytes(KEY_BYTES);
}

// ---------------------------------------------------------------------------
// Symmetric encryption: AES-256-GCM, output = iv (12 bytes) || ciphertext+tag
// ---------------------------------------------------------------------------

async function aesKey(raw: Uint8Array, usage: ("encrypt" | "decrypt")[]): Promise<CryptoKey> {
  if (raw.length !== KEY_BYTES) throw new TypeError(`Key must be ${KEY_BYTES} bytes`);
  return subtle.importKey("raw", buf(raw), { name: "AES-GCM" }, false, usage);
}

/**
 * Encrypts `plaintext` with a 32-byte key. `aad` binds the ciphertext to its context (for a Dipp, its link ID),
 * so ciphertext copied to another link will not decrypt.
 */
export async function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const iv = randomBytes(IV_BYTES);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: buf(iv), additionalData: buf(aad) },
    await aesKey(key, ["encrypt"]),
    buf(plaintext),
  );
  return concat(iv, new Uint8Array(ct));
}

export async function decrypt(key: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (sealed.length < IV_BYTES + 16) throw new DecryptError();
  try {
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: buf(sealed.subarray(0, IV_BYTES)), additionalData: buf(aad) },
      await aesKey(key, ["decrypt"]),
      buf(sealed.subarray(IV_BYTES)),
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptError();
  }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

export const PBKDF2_ITERATIONS = 600_000;

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array> {
  const base = await subtle.importKey("raw", buf(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(utf8.encode(info)) },
    base,
    KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

async function pbkdf2(secret: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  if (!Number.isInteger(iterations) || iterations < 1) throw new RangeError("Bad iteration count");
  const base = await subtle.importKey("raw", buf(utf8.encode(secret.normalize("NFKC"))), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: buf(salt), iterations },
    base,
    KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

/**
 * The key for a passphrase-protected Dipp: both the link key AND the passphrase are needed.
 * A leaked link alone can't be opened, and a guessed passphrase alone is useless without the link.
 */
export async function passphraseKey(
  linkKey: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<Uint8Array> {
  const stretched = await pbkdf2(passphrase, salt, iterations);
  return hkdf(concat(linkKey, stretched), salt, "dippme passphrase v1");
}

/** The key for a Creator "fan code" item. Only as strong as the code: codes must be 10+ characters. */
export const FAN_CODE_MIN_LENGTH = 10;

export async function fanCodeKey(
  code: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<Uint8Array> {
  if (code.trim().length < FAN_CODE_MIN_LENGTH) {
    throw new RangeError(`Fan codes must be at least ${FAN_CODE_MIN_LENGTH} characters`);
  }
  const stretched = await pbkdf2(code.trim(), salt, iterations);
  return hkdf(stretched, salt, "dippme fan code v1");
}

// ---------------------------------------------------------------------------
// Sealing to a public key (card approvals, room key handoff): ECDH P-256 + HKDF + AES-256-GCM
// ---------------------------------------------------------------------------

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

// Browser and Workers type definitions disagree on these shapes (Workers spells `public` as `$public`),
// though both runtimes accept the standard form. These helpers keep one source for both.
type DeriveParams = Parameters<SubtleCrypto["deriveBits"]>[0];
const ecdhWith = (pub: CryptoKey) => ({ name: "ECDH", public: pub }) as unknown as DeriveParams;
const newPair = async (extractable: boolean) =>
  (await subtle.generateKey(ECDH, extractable, ["deriveBits"])) as CryptoKeyPair;

/** A device or browser key pair. The private key is non-extractable: it can't be read out of storage. */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return newPair(false);
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return b64u.encode(new Uint8Array((await subtle.exportKey("raw", key)) as ArrayBuffer));
}

async function importPublicKey(encoded: string): Promise<CryptoKey> {
  try {
    return await subtle.importKey("raw", buf(b64u.decode(encoded)), ECDH, false, []);
  } catch {
    throw new TypeError("Invalid public key");
  }
}

async function sealKey(shared: Uint8Array, ephemeralPub: string, recipientPub: string): Promise<Uint8Array> {
  // Binding both public keys into the salt ties the derived key to this exact pair.
  return hkdf(shared, utf8.encode(`${ephemeralPub}.${recipientPub}`), "dippme seal v1");
}

export interface Sealed {
  /** The one-off sender public key. */
  epk: string;
  /** iv || ciphertext, base64url. */
  box: string;
}

/** Encrypts `plaintext` so only the holder of `recipientPub`'s private key can read it. */
export async function seal(recipientPub: string, plaintext: Uint8Array, aad: Uint8Array): Promise<Sealed> {
  const recipient = await importPublicKey(recipientPub);
  const ephemeral = await newPair(true);
  const epk = await exportPublicKey(ephemeral.publicKey);
  const shared = new Uint8Array(await subtle.deriveBits(ecdhWith(recipient), ephemeral.privateKey, 256));
  const key = await sealKey(shared, epk, recipientPub);
  return { epk, box: b64u.encode(await encrypt(key, plaintext, aad)) };
}

export async function openSealed(
  recipient: CryptoKeyPair,
  sealed: Sealed,
  aad: Uint8Array,
): Promise<Uint8Array> {
  let shared: Uint8Array;
  try {
    const sender = await importPublicKey(sealed.epk);
    shared = new Uint8Array(await subtle.deriveBits(ecdhWith(sender), recipient.privateKey, 256));
  } catch {
    throw new DecryptError();
  }
  const key = await sealKey(shared, sealed.epk, await exportPublicKey(recipient.publicKey));
  let box: Uint8Array;
  try {
    box = b64u.decode(sealed.box);
  } catch {
    throw new DecryptError();
  }
  return decrypt(key, box, aad);
}

// ---------------------------------------------------------------------------
// Links: https://dipp.chat/l#{secret} for a Dipp, https://dipp.chat/r#{secret} for a room,
// with ".p" on the end when a passphrase is also needed.
//
// One 16-byte secret (22 characters) per link. The ID the server stores things under and the AES-256 key are
// both derived from it with HKDF, which can't be reversed: the server sees only the ID, never the secret, so
// it still can't decrypt anything. 128 bits of secret is far beyond guessing.
// ---------------------------------------------------------------------------

export const LINK_SECRET_BYTES = 16;
/**
 * Every kind of link-secret link. Each kind derives different IDs and keys from the same secret.
 * moment: Swap a moment. yes: Mutual yes. ask: Send me that photo. shot: Direct my next shot.
 */
export type LinkKind = "dipp" | "room" | "moment" | "yes" | "ask" | "shot";
/** The path letter each kind uses: dipp.chat/l#..., /r#..., /m#..., /y#..., /a#..., /s#... */
export const LINK_PATH: Record<LinkKind, string> = { dipp: "l", room: "r", moment: "m", yes: "y", ask: "a", shot: "s" };

export interface LinkParts {
  /** What the server stores the Dipp or room under (22 characters). */
  id: string;
  /** The 32-byte AES-256-GCM key. Never leaves the device. */
  key: Uint8Array;
}

export interface ParsedLink {
  secret: Uint8Array;
  passphrase: boolean;
}

export function newLinkSecret(): Uint8Array {
  return randomBytes(LINK_SECRET_BYTES);
}

/** Derives a link's ID and key from its secret. A Dipp and a room with the same secret get different IDs and keys. */
export async function linkParts(kind: LinkKind, secret: Uint8Array): Promise<LinkParts> {
  if (secret.length !== LINK_SECRET_BYTES) throw new TypeError(`A link secret is ${LINK_SECRET_BYTES} bytes`);
  const salt = utf8.encode(`dippme ${kind} link v2`);
  const idBytes = (await hkdf(secret, salt, "id")).subarray(0, ID_BYTES);
  return { id: b64u.encode(idBytes), key: await hkdf(secret, salt, "key") };
}

export function linkUrl(base: string, kind: LinkKind, secret: Uint8Array, passphrase = false): string {
  return `${base.replace(/\/+$/, "")}/${LINK_PATH[kind]}#${b64u.encode(secret)}${passphrase ? ".p" : ""}`;
}

/** Parses the part after the #. Returns null for anything that isn't a well-formed link secret. */
export function parseLinkFragment(fragment: string): ParsedLink | null {
  const text = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const match = /^([A-Za-z0-9_-]{22})(\.p)?$/.exec(text);
  if (!match) return null;
  const secret = b64u.decode(match[1]!);
  if (secret.length !== LINK_SECRET_BYTES) return null;
  return { secret, passphrase: match[2] === ".p" };
}

/** The associated data that binds a Dipp's ciphertext to its link ID. */
export function dippAad(id: string, part: "content" | "prompt" = "content"): Uint8Array {
  return utf8.encode(`dippme/dipp/${part}/${id}`);
}

/** Associated data for the parts of a moment, mutual yes, ask or shot, so a part can't be moved elsewhere. */
export function partAad(kind: Exclude<LinkKind, "dipp" | "room">, id: string, part: string): Uint8Array {
  return utf8.encode(`dippme/${kind}/${part}/${id}`);
}

type PartKind = Exclude<LinkKind, "dipp" | "room">;

/** Encrypts one part (a photo, a prompt, a note) under a link key, bound to its kind, ID and name. */
export async function sealPart(key: Uint8Array, kind: PartKind, id: string, part: string, plaintext: Uint8Array): Promise<string> {
  return b64u.encode(await encrypt(key, plaintext, partAad(kind, id, part)));
}

export async function openPart(key: Uint8Array, kind: PartKind, id: string, part: string, sealed: string): Promise<Uint8Array> {
  let bytes: Uint8Array;
  try {
    bytes = b64u.decode(sealed);
  } catch {
    throw new DecryptError();
  }
  return decrypt(key, bytes, partAad(kind, id, part));
}

/**
 * Mutual yes. Both sides derive the same 32 bytes for "yes" from the link key, and "no" is fresh random
 * bytes, so the server can see only whether two answers are equal (both said yes), never which way one went.
 */
export async function yesAnswer(key: Uint8Array, id: string, yes: boolean): Promise<string> {
  return b64u.encode(yes ? await hkdf(key, utf8.encode(`dippme yes ${id}`), "yes") : randomBytes(KEY_BYTES));
}
