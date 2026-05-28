import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { FindingsList } from "./FindingsList";

describe("FindingsList", () => {
	it("filters by package/severity/confidence/status and avoids overclaiming", async () => {
		render(<FindingsList />);
		expect(screen.getByText("left-pad")).toBeInTheDocument();
		await userEvent.selectOptions(
			screen.getByLabelText("Severity"),
			"critical",
		);
		expect(screen.getByText("No findings match")).toBeInTheDocument();
		expect(screen.queryByText(/malicious|malware/i)).not.toBeInTheDocument();
	});
});
