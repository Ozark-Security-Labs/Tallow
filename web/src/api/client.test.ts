import { describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./client";

describe("ApiClient", () => {
	it("sends credentials and parses successful JSON", async () => {
		const fetchMock = vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify({ items: [] }), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		const result = await new ApiClient("/v1").providers();
		expect(result.items).toEqual([]);
		const firstCall = fetchMock.mock.calls[0];
		expect(firstCall?.[1]?.credentials).toBe("include");
	});

	it("normalizes API errors", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							error: {
								code: "permission_denied",
								message: "permission denied",
							},
						}),
						{ status: 403 },
					),
			),
		);
		await expect(
			new ApiClient("/v1").notificationRoutes(),
		).rejects.toMatchObject({
			code: "permission_denied",
			status: 403,
		} satisfies Partial<ApiError>);
	});
});
