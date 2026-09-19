import { describe, expect, it, vi } from "vitest";
import { MegaHttpClient } from "../mega-client.js";

describe("MegaHttpClient.getDevicePublicKey", () => {
  it("queries the cloud endpoint for device public key and caches it", async () => {
    const mockFetch = vi.fn(async (url: string | URL | Request) => {
      expect(url.toString()).toContain("/v1/app/public_key/query?device_sn=T8520K0000000000&type=2");
      return new Response(
        JSON.stringify({
          code: 0,
          msg: "Succeed",
          data: {
            public_key:
              "04aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    vi.stubGlobal("fetch", mockFetch);

    try {
      const mega = new MegaHttpClient({
        email: "synthetic@example.invalid",
        password: "synthetic",
      });

      // Inject auth credentials
      (mega as any).auth_ = {
        userId: "synthetic-user-id",
        authToken: "synthetic-token",
      };

      const key1 = await mega.getDevicePublicKey("T8520K0000000000");
      expect(key1).toBe(
        "04aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      );
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call should return cached key without fetching again
      const key2 = await mega.getDevicePublicKey("T8520K0000000000");
      expect(key2).toBe(key1);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("throws descriptive error when response code is non-zero", async () => {
    const mockFetch = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          code: 10002,
          msg: "Device not found",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    vi.stubGlobal("fetch", mockFetch);

    try {
      const mega = new MegaHttpClient({
        email: "synthetic@example.invalid",
        password: "synthetic",
      });
      (mega as any).auth_ = {
        userId: "synthetic-user-id",
        authToken: "synthetic-token",
      };

      await expect(mega.getDevicePublicKey("T8520K9999999999")).rejects.toThrow(
        "Failed to fetch device public key for T8520K9999999999 (200/10002): Device not found",
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
