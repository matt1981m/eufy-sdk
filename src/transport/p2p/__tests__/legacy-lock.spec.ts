import { describe, it, expect, vi } from "vitest";
import { createECDH, createDecipheriv, createHmac } from "node:crypto";
import { isLegacyLock, getLockVectorBytes, eufyKDF, buildLegacyLockPayload } from "../legacy-lock.js";
import { CommandType } from "../commands.js";
import { P2PCommandRouter, type P2PRouterDeps } from "../command-router.js";
import type { EufyDevice } from "../../../core/types.js";
import { P2PSession } from "../p2p-session.js";

describe("isLegacyLock", () => {
  it("identifies legacy lock models (T8520, T8500, T8510, T8501) as legacy", () => {
    expect(isLegacyLock("T8520", "T8520K1111111111")).toBe(true);
    expect(isLegacyLock("T8500", "T8500K1111111111")).toBe(true);
    expect(isLegacyLock("T8510", "T8510K1111111111")).toBe(true);
    expect(isLegacyLock("T8501", "T8501K1111111111")).toBe(true);
    expect(isLegacyLock(undefined, "T8520K1111111111")).toBe(true);
  });

  it("identifies modern ff09 locks as non-legacy", () => {
    expect(isLegacyLock("T8531", "T8531K1111111111")).toBe(false);
    expect(isLegacyLock("T85D0", "T85D0K1111111111")).toBe(false);
    expect(isLegacyLock("T85L0", "T85L0K1111111111")).toBe(false);
    expect(isLegacyLock("T85V0", "T85V0K1111111111")).toBe(false);
    expect(isLegacyLock("T85P0", "T85P0K1111111111")).toBe(false);
    expect(isLegacyLock("T8502", "T8502K1111111111")).toBe(false);
    expect(isLegacyLock("T8506", "T8506K1111111111")).toBe(false);
    expect(isLegacyLock("T8510P", "T8510PK111111111")).toBe(false);
    expect(isLegacyLock("T8520P", "T8520PK111111111")).toBe(false);
    // T8520 serial with '8' or '9' at index 6 (T8510P/T8520P hardware revisions)
    expect(isLegacyLock("T8520", "T8520K8111111111")).toBe(false);
    expect(isLegacyLock("T8520", "T8520K9111111111")).toBe(false);
  });

  it("returns false for non-lock models", () => {
    expect(isLegacyLock("T8111", "T8111K1111111111")).toBe(false);
    expect(isLegacyLock("T8010", "T8010K1111111111")).toBe(false);
  });
});

describe("getLockVectorBytes", () => {
  it("converts 16-character serial number to 16-byte ASCII IV", () => {
    const iv = getLockVectorBytes("T8520K0000000000");
    expect(iv.length).toBe(16);
    expect(iv.toString("ascii")).toBe("T8520K0000000000");
  });

  it("zero-pads serial numbers shorter than 16 characters", () => {
    const iv = getLockVectorBytes("T8520");
    expect(iv.length).toBe(16);
    expect(iv.subarray(0, 5).toString("ascii")).toBe("T8520");
    expect(iv.subarray(5).every((b) => b === 0)).toBe(true);
  });

  it("truncates serial numbers longer than 16 characters", () => {
    const iv = getLockVectorBytes("T8520K0000000000EXTRA");
    expect(iv.length).toBe(16);
    expect(iv.toString("ascii")).toBe("T8520K0000000000");
  });
});

describe("eufyKDF", () => {
  it("derives requested length buffer using HMAC-SHA256 with ECIES salt", () => {
    const secret = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
    const kdf48 = eufyKDF(secret, 48);
    expect(kdf48.length).toBe(48);
    const kdf32 = eufyKDF(secret, 32);
    expect(kdf32.length).toBe(32);
    expect(kdf32).toEqual(kdf48.subarray(0, 32));
  });
});

describe("buildLegacyLockPayload cryptographic roundtrip", () => {
  it("generates an outer envelope and encrypted payload that decrypts correctly with lock ECDH private key", () => {
    // Simulate lock ECDH keypair
    const lockEcdh = createECDH("prime256v1");
    lockEcdh.generateKeys();
    // Device public key query returns uncompressed point (without 04 prefix or with it)
    const lockPubHex = lockEcdh.getPublicKey("hex").slice(2);

    const clientEcdh = createECDH("prime256v1");
    clientEcdh.generateKeys();

    const testKey = "0123456789ABCDEF0123456789ABCDEF";
    const testRandomValue = Buffer.from("fedcba9876543210fedcba9876543210", "hex");

    const jsonStr = buildLegacyLockPayload({
      engage: true,
      adminUserId: "admin_user_999",
      username: "Alice",
      shortUserId: "short_42",
      deviceSn: "T8520K0000000000",
      lockPublicKey: lockPubHex,
      channel: 0,
      seqNum: 777,
      key: testKey,
      randomValue: testRandomValue,
      clientEcdh,
    });

    expect(jsonStr).toContain("\\u003d");
    const parsedEnvelope = JSON.parse(jsonStr.replace(/\\u003d/g, "="));
    expect(parsedEnvelope.cmd).toBe(CommandType.P2P_ON_OFF_LOCK);
    expect(parsedEnvelope.account_id).toBe("admin_user_999");
    expect(parsedEnvelope.mChannel).toBe(0);
    expect(parsedEnvelope.mValue3).toBe(0);

    // 1. Decrypt ecdhKey using lock's ECDH private key
    const ecdhKeyBuf = Buffer.from(parsedEnvelope.key, "hex");
    expect(ecdhKeyBuf.length).toBe(129); // 33 + 16 + 48 + 32

    const clientPubKey = ecdhKeyBuf.subarray(0, 33);
    const randomVal = ecdhKeyBuf.subarray(33, 49);
    const encKeyData = ecdhKeyBuf.subarray(49, 97);
    const hmacSig = ecdhKeyBuf.subarray(97, 129);

    const lockSecret = lockEcdh.computeSecret(clientPubKey);
    const derived = eufyKDF(lockSecret, 48);
    const lockAesKey = derived.subarray(0, 16);
    const lockHmacKey = derived.subarray(16, 48);

    const checkHmac = createHmac("sha256", lockHmacKey).update(randomVal).update(encKeyData).digest();
    expect(checkHmac).toEqual(hmacSig);

    const decipher = createDecipheriv("aes-128-cbc", lockAesKey, randomVal);
    const recoveredKey = Buffer.concat([decipher.update(encKeyData), decipher.final()]).toString("utf8");
    expect(recoveredKey).toBe(testKey);

    // 2. Decrypt inner payload using recovered AES key + deviceSn IV
    const innerCiphertext = Buffer.from(parsedEnvelope.payload, "base64");
    const innerDecipher = createDecipheriv(
      "aes-128-cbc",
      Buffer.from(recoveredKey, "hex"),
      getLockVectorBytes("T8520K0000000000"),
    );
    const innerPlaintext = Buffer.concat([innerDecipher.update(innerCiphertext), innerDecipher.final()]).toString(
      "utf8",
    );

    const innerObj = JSON.parse(innerPlaintext);
    expect(innerObj).toEqual({
      shortUserId: "short_42",
      slOperation: 1, // engage: true -> 1 (locked)
      userId: "admin_user_999",
      userName: "Alice",
      seq_num: 777,
    });
  });

  it("sets slOperation to 0 when engage is false (unlock)", () => {
    const lockEcdh = createECDH("prime256v1");
    lockEcdh.generateKeys();
    const lockPubHex = lockEcdh.getPublicKey("hex"); // full hex with 04

    const testKey = "AABBCCDDEEFF00112233445566778899";
    const jsonStr = buildLegacyLockPayload({
      engage: false,
      adminUserId: "admin_1",
      username: "Bob",
      shortUserId: "2",
      deviceSn: "T8520K0000000000",
      lockPublicKey: lockPubHex,
      channel: 0,
      seqNum: 123,
      key: testKey,
    });

    const parsedEnvelope = JSON.parse(jsonStr.replace(/\\u003d/g, "="));
    const innerCiphertext = Buffer.from(parsedEnvelope.payload, "base64");
    const innerDecipher = createDecipheriv(
      "aes-128-cbc",
      Buffer.from(testKey, "hex"),
      getLockVectorBytes("T8520K0000000000"),
    );
    const innerPlaintext = Buffer.concat([innerDecipher.update(innerCiphertext), innerDecipher.final()]).toString(
      "utf8",
    );

    const innerObj = JSON.parse(innerPlaintext);
    expect(innerObj.slOperation).toBe(0); // engage: false -> 0 (unlocked)
  });
});

describe("P2PCommandRouter legacy lock dispatch", () => {
  it("routes ff09-actuate to legacy command 1961 when target device is a legacy lock (T8520)", async () => {
    const lockSn = "T8520K0000000000";
    const lockDevice: EufyDevice = {
      sn: lockSn,
      model: "T8520",
      category: "eufy_security",
      deviceClass: "other",
      api: "mega",
      realtime: "p2p",
      stationSn: lockSn,
    };

    const lockEcdh = createECDH("prime256v1");
    lockEcdh.generateKeys();
    const mockLockPub = lockEcdh.getPublicKey("hex").slice(2);

    const sentStrings: Array<{ cmd: number; value: string; channel: number }> = [];

    const mockSession = {
      cfg: { stationSn: lockSn },
      isConnected: true,
      hasLevel2Key: false, // Level 1 standalone lock
      connectAddress: { host: "192.168.1.100", port: 32100 },
      sendStringPayloadCommand: vi.fn((cmd: number, value: string, channel: number) => {
        sentStrings.push({ cmd, value, channel });
      }),
      sendRawLevel2: vi.fn(),
      awaitLevel2Key: vi.fn(async () => false),
      repromptLevel2Key: vi.fn(() => false),
      on: vi.fn(),
      off: vi.fn(),
      once: vi.fn(),
    } as unknown as P2PSession;

    const mockMega = {
      getDevicePublicKey: vi.fn(async (sn: string) => {
        expect(sn).toBe(lockSn);
        return mockLockPub;
      }),
      auth: { userId: "admin_user_123" },
    };

    const deps: P2PRouterDeps = {
      mega: mockMega as unknown as P2PRouterDeps["mega"],
      listDevices: () => [lockDevice],
      ensureDevices: async () => {},
      onConnect: vi.fn(),
      onClose: vi.fn(),
      onError: vi.fn(),
      onLevel2Ready: vi.fn(),
      onFrame: vi.fn(),
    };

    const router = new P2PCommandRouter(deps);
    (router as any).manager.register(lockSn, mockSession);

    await router.dispatchCommand(lockSn, {
      kind: "ff09-actuate",
      engage: true,
      adminUserId: "admin_user_123",
      username: "Admin",
      shortUserId: "1",
      deviceSn: lockSn,
    });

    expect(mockMega.getDevicePublicKey).toHaveBeenCalledWith(lockSn);
    expect(sentStrings.length).toBe(5); // DIRECT_CMD_SENDS = 5
    expect(sentStrings[0].cmd).toBe(CommandType.CMD_SET_PAYLOAD);
    expect(sentStrings[0].channel).toBe(0);

    const envelope = JSON.parse(sentStrings[0].value.replace(/\\u003d/g, "="));
    expect(envelope.cmd).toBe(CommandType.P2P_ON_OFF_LOCK); // 1961
    expect(envelope.account_id).toBe("admin_user_123");
    expect(envelope.mChannel).toBe(0);
    expect(envelope.mValue3).toBe(0);
    expect(envelope.key).toBeDefined();
    expect(envelope.payload).toBeDefined();
  });

  it("routes ff09-actuate to modern ff09 frame when target device is a modern lock (T85L0)", async () => {
    const modernSn = "T85L0K0000000000";
    const modernDevice: EufyDevice = {
      sn: modernSn,
      model: "T85L0",
      category: "eufy_security",
      deviceClass: "other",
      api: "mega",
      realtime: "p2p",
      stationSn: modernSn,
    };

    const mockSession = {
      cfg: { stationSn: modernSn },
      isConnected: true,
      hasLevel2Key: true,
      connectAddress: { host: "192.168.1.100", port: 32100 },
      sendControlLevel2: vi.fn(() => true),
      awaitLevel2Key: vi.fn(async () => true),
      repromptLevel2Key: vi.fn(() => false),
      on: vi.fn(),
      off: vi.fn(),
      once: vi.fn(),
    } as unknown as P2PSession;

    const mockMega = {
      getDevicePublicKey: vi.fn(),
      auth: { userId: "admin_user_123" },
    };

    const deps: P2PRouterDeps = {
      mega: mockMega as unknown as P2PRouterDeps["mega"],
      listDevices: () => [modernDevice],
      ensureDevices: async () => {},
      onConnect: vi.fn(),
      onClose: vi.fn(),
      onError: vi.fn(),
      onLevel2Ready: vi.fn(),
      onFrame: vi.fn(),
    };

    const router = new P2PCommandRouter(deps);
    (router as any).manager.register(modernSn, mockSession);

    await router.dispatchCommand(modernSn, {
      kind: "ff09-actuate",
      engage: true,
      adminUserId: "admin_user_123",
      username: "Admin",
      shortUserId: "01",
      deviceSn: modernSn,
    });

    // Modern lock should NOT query cloud public key
    expect(mockMega.getDevicePublicKey).not.toHaveBeenCalled();
    // Modern lock should send via sendControlLevel2 with CMD_TRANSFER_PAYLOAD (1940)
    expect(mockSession.sendControlLevel2).toHaveBeenCalled();
    const calls = (mockSession.sendControlLevel2 as any).mock.calls;
    expect(calls[0][0]).toBe(1940); // CMD_TRANSFER_PAYLOAD
    expect(calls[0][3].apiCommand).toBe(6018); // ff09 lock apiCommand
  });
});
