import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../../auth/AuthContext";
import { AlertDetail } from "./AlertDetail";

vi.stubGlobal(
	"fetch",
	vi.fn(
		async () =>
			new Response(
				JSON.stringify({
					user: {
						id: "u1",
						email: "analyst@example.com",
						roles: ["analyst"],
						status: "active",
					},
					capabilities: ["findings:triage"],
				}),
				{ status: 200 },
			),
	),
);

describe("AlertDetail", () => {
	it("shows alert evidence links and triage action area", async () => {
		render(
			<AuthProvider>
				<AlertDetail />
			</AuthProvider>,
		);
		expect(screen.getByText("Alert detail")).toBeInTheDocument();
		expect(screen.getByText(/delivery attempts/i)).toBeInTheDocument();
		expect(await screen.findByText("Acknowledge finding")).toBeInTheDocument();
	});
});
