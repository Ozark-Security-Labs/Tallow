import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ImpactPaths } from "./ImpactPaths";

describe("ImpactPaths", () => {
	it("shows impact paths without intrinsic compromise overclaiming", () => {
		render(<ImpactPaths />);
		expect(screen.getByText("Impact paths")).toBeInTheDocument();
		expect(
			screen.getByText(/not automatically classified as compromised/i),
		).toBeInTheDocument();
	});
});
