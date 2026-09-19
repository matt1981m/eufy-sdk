/**
 * Legacy Smart Lock P2P actuation protocol (command 1961 / CMD_SMARTLOCK_REMOTE_CONTROL).
 *
 * Used by older P2P locks such as the Smart Lock Touch & Wi-Fi (T8520), Smart Lock Touch (T8500),
 * Smart Lock Wi-Fi Bridge (T8510), and D20 (T8501). Unlike modern locks (T8531, T85D0, T85L0,
 * T85V0, T85P0, T8502, T8506, T8510P, T8520P) which actuate via `CMD_TRANSFER_PAYLOAD` (1940)
 * wrapping the `ff09` AES-128-CBC frame (apiCommand 6018), legacy locks time out on `ff09`
 * and require command 1961 (`P2P_ON_OFF_LOCK`) in a `CMD_SET_PAYLOAD` (1350) envelope.
 *
 * Wire payload structure:
 *  - Outer envelope (CMD_SET_PAYLOAD 1350):
 *    {
 *      key: <ecdhKeyHex (258 hex chars / 129 bytes)>,
 *      account_id: <adminUserId>,
 *      cmd: 1961,
 *      mChannel: <channel>,
 *      mValue3: 0,
 *      payload: <encPayloadBase64>
 *    }
 *
 *  - Nested inner payload (plaintext before AES-128-CBC):
 *    {
 *      shortUserId: <shortUserId>,
 *      slOperation: <engage ? 1 : 0>,
 *      userId: <adminUserId>,
 *      userName: <username>,
 *      seq_num: <random 0..999>
 *    }
 *
 *  - Inner cipher:
 *    Key: 16 random bytes as 32 hex chars.
 *    IV: device SN encoded as ASCII bytes, zero-padded to 16 bytes.
 *    Plaintext: JSON-encoded nested payload, AES-128-CBC PKCS#7 encrypted, Base64-encoded.
 *
 *  - Key exchange (`ecdhKey`):
 *    Device public key queried from cloud: `v1/app/public_key/query?device_sn=${sn}&type=2`.
 *    ECDH curve: `prime256v1`.
 *    KDF: HMAC-SHA256 with salt "ECIES" deriving 48 bytes (16-byte AES key + 32-byte HMAC key).
 *    Plaintext: 32 ASCII bytes of the 32-hex-char AES key, encrypted with AES-128-CBC.
 *    HMAC: HMAC-SHA256 over (randomValue || encryptedData).
 *    Envelope: compressed client pubkey (33B) || randomValue (16B) || ciphertext (48B) || hmac (32B).
 */
import { createCipheriv, createECDH, createHmac, randomBytes, type ECDH } from "node:crypto";
import { CommandType } from "./commands.js";

/** Input required to construct a legacy lock actuation payload. */
export interface LegacyLockPayloadInput {
  /** `true` to engage lock (lock door), `false` to disengage (unlock door). */
  engage: boolean;
  /** Admin account user ID owning the device. */
  adminUserId: string;
  /** Acting username for event log attribution. */
  username: string;
  /** Short user ID of the admin. */
  shortUserId: string;
  /** Device serial number. */
  deviceSn: string;
  /** Device ECDH public key retrieved from the cloud API (64 hex bytes X/Y or 65 hex bytes 04+X+Y). */
  lockPublicKey: string;
  /** Channel on the P2P session (typically 0 for standalone locks). */
  channel: number;
  /** Optional sequence number (0..999); randomized if omitted. */
  seqNum?: number;
  /** Optional 32-hex-char AES key override (for deterministic testing). */
  key?: string;
  /** Optional 16-byte randomValue override for ECIES (for deterministic testing). */
  randomValue?: Buffer;
  /** Optional ECDH keypair override (for deterministic testing). */
  clientEcdh?: ECDH;
}

/**
 * Identify whether a device model / serial belongs to the legacy lock family that
 * requires P2P command 1961 rather than modern ff09 framing.
 */
export function isLegacyLock(model?: string, sn?: string): boolean {
  const m = (model ?? "").toUpperCase();
  const s = (sn ?? "").toUpperCase();

  // Modern locks confirmed to use ff09 framing (apiCommand 6018 over 1940)
  if (m === "T8510P" || m === "T8520P") return false;
  if (
    (m.startsWith("T8520") || s.startsWith("T8520")) &&
    s.length > 6 &&
    (s.charAt(6) === "8" || s.charAt(6) === "9")
  ) {
    return false;
  }
  if (/^T85(31|D0|L0|V0|P0|02|06)/i.test(m) || /^T85(31|D0|L0|V0|P0|02|06)/i.test(s)) {
    return false;
  }

  // Any other T85 lock (T8520, T8500, T8510, T8501, etc.) requires legacy cmd 1961
  return m.startsWith("T85") || s.startsWith("T85");
}

/**
 * Eufy KDF: HMAC-SHA256 with static salt "ECIES" deriving `digestLength` bytes.
 * Step 0: tmpBuffer = HMAC(secret, "ECIES"), digest0 = HMAC(secret, tmpBuffer || "ECIES")
 * Step 1: tmpBuffer = HMAC(secret, tmpBuffer), digest1 = HMAC(secret, tmpBuffer || "ECIES")
 */
export function eufyKDF(secret: Buffer, digestLength = 48): Buffer {
  const hashLength = 32;
  const staticBuffer = Buffer.from("ECIES", "ascii");
  const steps = Math.ceil(digestLength / hashLength);
  const out = Buffer.alloc(hashLength * steps);
  let tmpBuffer = staticBuffer;
  for (let step = 0; step < steps; ++step) {
    tmpBuffer = createHmac("sha256", secret).update(tmpBuffer).digest();
    const digest = createHmac("sha256", secret)
      .update(Buffer.concat([tmpBuffer, staticBuffer]))
      .digest();
    digest.copy(out, hashLength * step);
  }
  return out.subarray(0, digestLength);
}

/**
 * Derive the 16-byte IV for the inner lock payload from the device serial number.
 * ASCII bytes of deviceSn zero-padded or truncated to 16 bytes.
 */
export function getLockVectorBytes(deviceSn: string): Buffer {
  const buf = Buffer.alloc(16, 0);
  const snBuf = Buffer.from(deviceSn, "ascii");
  snBuf.copy(buf, 0, 0, Math.min(snBuf.length, 16));
  return buf;
}

/**
 * Encrypt the 32-hex-char AES key using ECIES with the device's public key.
 * Returns a 258-character hex string (129 bytes: 33B pubkey + 16B IV + 48B ciphertext + 32B HMAC).
 */
export function getAdvancedLockKey(
  key: string,
  publicKey: string,
  opts: { randomValue?: Buffer; clientEcdh?: ECDH } = {},
): string {
  const ecdh = opts.clientEcdh ?? createECDH("prime256v1");
  if (!opts.clientEcdh) {
    ecdh.generateKeys();
  }

  const cleanPub = publicKey.replace(/^0x/i, "");
  const pubBuf = Buffer.from(cleanPub, "hex");
  const peerKey = pubBuf.length === 65 && pubBuf[0] === 0x04 ? pubBuf : Buffer.concat([Buffer.from([0x04]), pubBuf]);
  const secret = ecdh.computeSecret(peerKey);
  const derivedKey = eufyKDF(secret, 48);

  const aesKey = derivedKey.subarray(0, 16);
  const hmacKey = derivedKey.subarray(16, 48);

  const randomValue = opts.randomValue ?? randomBytes(16);
  const cipher = createCipheriv("aes-128-cbc", aesKey, randomValue);
  const encryptedData = Buffer.concat([cipher.update(Buffer.from(key, "utf8")), cipher.final()]);

  const hmac = createHmac("sha256", hmacKey);
  hmac.update(randomValue);
  hmac.update(encryptedData);
  const hmacDigest = hmac.digest();

  return Buffer.concat([
    Buffer.from(ecdh.getPublicKey("hex", "compressed"), "hex"),
    randomValue,
    encryptedData,
    hmacDigest,
  ]).toString("hex");
}

/**
 * Build the JSON wire string for legacy lock actuation (command 1961).
 * Output is formatted with escaped equals signs (`\u003d`), matching eufy firmware expectation.
 */
export function buildLegacyLockPayload(input: LegacyLockPayloadInput): string {
  // 1. Generate or use supplied 32-hex-char AES key (16 random bytes uppercase)
  const key = input.key ?? randomBytes(16).toString("hex").toUpperCase();

  // 2. Encrypt key via ECDH ECIES
  const ecdhKey = getAdvancedLockKey(key, input.lockPublicKey, {
    randomValue: input.randomValue,
    clientEcdh: input.clientEcdh,
  });

  // 3. Build and encrypt inner payload
  const nestedPayload = {
    shortUserId: input.shortUserId,
    slOperation: input.engage ? 1 : 0,
    userId: input.adminUserId,
    userName: input.username,
    seq_num: input.seqNum ?? Math.floor(Math.random() * 1000),
  };

  const iv = getLockVectorBytes(input.deviceSn);
  const innerCipher = createCipheriv("aes-128-cbc", Buffer.from(key, "hex"), iv);
  const encPayload = Buffer.concat([
    innerCipher.update(Buffer.from(JSON.stringify(nestedPayload), "utf8")),
    innerCipher.final(),
  ]);

  // 4. Construct outer envelope
  const outerEnvelope = {
    key: ecdhKey,
    account_id: input.adminUserId,
    cmd: CommandType.P2P_ON_OFF_LOCK,
    mChannel: input.channel,
    mValue3: 0,
    payload: encPayload.toString("base64"),
  };

  return JSON.stringify(outerEnvelope).replace(/=/g, "\\u003d");
}
