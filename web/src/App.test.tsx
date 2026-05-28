import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

beforeEach(() => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string) => {
			if (url.endsWith("/auth/me"))
				return new Response(
					JSON.stringify({
						user: {
							id: "u1",
							email: "admin@example.com",
							roles: ["admin"],
							status: "active",
						},
						capabilities: ["settings:mutate"],
					}),
					{ status: 200 },
				);
			return new Response(JSON.stringify({ items: [] }), { status: 200 });
		}),
	);
});

describe("App shell", () => {
	it("renders navigation routes and dashboard", async () => {
		render(<App />);
		expect(
			await screen.findByRole("heading", { name: "Dashboard" }),
		).toBeInTheDocument();
		expect(screen.getByText("Packages")).toBeInTheDocument();
		expect(screen.getByText("Findings")).toBeInTheDocument();
		expect(screen.getByText("Impact")).toBeInTheDocument();
		expect(screen.getByText("Analyzer runs")).toBeInTheDocument();
		expect(await screen.findByText("admin@example.com")).toBeInTheDocument();
	});
});
