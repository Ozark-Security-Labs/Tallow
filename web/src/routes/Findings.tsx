import { FindingDetail } from "./findings/FindingDetail";
import { FindingsList } from "./findings/FindingsList";
export function Findings() {
	return window.location.pathname.includes("/findings/") ? (
		<FindingDetail />
	) : (
		<FindingsList />
	);
}
