import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Login } from "./Login";

describe("Login", () => {
	it("renders provider-driven local and GitHub login controls", async () => {
		const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/auth/providers"))
				return new Response(
					JSON.stringify({
						items: [
							{
								name: "local",
								provider: "local",
								type: "password",
								label: "Email",
								enabled: true,
							},
							{
								name: "github",
								type: "oauth",
								label: "GitHub",
								enabled: true,
								login_url: "/v1/auth/github/login",
							},
						],
					}),
					{ status: 200 },
				);
			if (url.endsWith("/auth/local/login") && init?.method === "POST")
				return new Response(
					JSON.stringify({
						user: {
							id: "u1",
							email: "admin@example.com",
							roles: ["admin"],
							status: "active",
						},
						capabilities: [],
					}),
					{ status: 200 },
				);
			return new Response("{}", { status: 404 });
		});
		vi.stubGlobal("fetch", fetchMock);
		render(<Login />);
		expect(await screen.findByText("Continue with GitHub")).toBeInTheDocument();
		await userEvent.type(screen.getByLabelText(/email/i), "admin@example.com");
		await userEvent.type(screen.getByLabelText(/password/i), "pw");
		await userEvent.click(screen.getByText("Sign in locally"));
		expect(fetchMock).toHaveBeenCalledWith(
			"/v1/auth/local/login",
			expect.objectContaining({ method: "POST" }),
		);
	});
});
