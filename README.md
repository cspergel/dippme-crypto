# @dippme/crypto

The code that encrypts what you share in [DippMe](https://dippme.com), published so anyone can check it.

DippMe makes one-time links, disappearing rooms and a private card. Everything is encrypted on your
device before it's sent, and the key travels only in the part of the link after the `#` (which browsers
never send to a server) or sealed to another device's public key. DippMe's server stores ciphertext it
can't read.

This repository is that encryption layer, exactly as the app and the web pages use it. The rest of DippMe
(the server, the app, the website) is not open source.

## What it does

| | How |
|---|---|
| Encrypt and decrypt | AES-256-GCM with a random 96-bit IV per message, and additional authenticated data that binds every ciphertext to the link and the part it belongs to, so a ciphertext can't be moved to another link or field |
| Links | One random 16-byte secret per link (22 characters after the `#`). The ID the server stores things under and the AES key are both derived from it with HKDF-SHA-256 using different labels, so the server sees only the ID and can't get the key from it. Each kind of link (a message, a room, a photo swap and so on) derives different IDs and keys from the same secret |
| Passphrases | PBKDF2-HMAC-SHA-256 (600,000 iterations, random salt), then combined with the link key through HKDF, so a passphrase-protected link needs both the link and the passphrase |
| Fan codes | PBKDF2-HMAC-SHA-256 (600,000 iterations, random salt) on the code alone, so an item is only as strong as its code; codes must be at least 10 characters |
| Sealing to a device | ECDH P-256 key agreement with a fresh ephemeral key per message, HKDF-SHA-256, then AES-256-GCM. Used to send a card approval only to the browser that asked, and to hand over room keys |
| Mutual yes | A "yes" is a value both sides derive from the shared link key with HKDF; a "no" is fresh random bytes. The server can see only whether two answers are equal (both said yes), never which way one went |

Only the platform's Web Crypto API is used: no hand-written cipher code and no runtime dependencies. It runs
in browsers, Cloudflare Workers, Node 20+ and, on the phone, through a Web Crypto implementation. Nothing in
here logs anything or talks to the network.

## What it doesn't do

Encryption protects what you share on the way and on DippMe's server. It can't stop the person you send
something to from screenshotting or copying it once it's open, and it doesn't hide that a link exists or
when it was opened. DippMe says "screenshot-resistant", never "screenshot-proof".

## Running the tests

```sh
pnpm install             # or npm install
npm test                 # unit tests (Node)
npx playwright install   # once, for the browser tests
npm run test:browsers    # the same code in Chromium, WebKit (Safari) and Firefox
npm run typecheck
```

The tests check real outputs: round trips; the cases that must fail (wrong key, ciphertext moved to another
link, a flipped bit or truncated data, the wrong recipient, a malformed key); and that the same secret gives
different IDs and keys for different kinds of link.

## Reporting a security problem

Please email **support@dippme.com** with details, and give us a reasonable chance to
fix it before sharing it publicly. More at [dippme.com/security](https://dippme.com/security/).

## License

MIT. Copyright 2026 Spergel Health AI LLC.
