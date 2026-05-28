import type {
	AuthProvider,
	CurrentUser,
	ErrorResponse,
	ListResponse,
	Finding,
	PackageSummary,
	AnalyzerRun,
	ImpactPath,
	Alert,
	NotificationRoute,
} from "./generated";

export class ApiError extends Error {
	code: string;
	status: number;
	requestId?: string;

	constructor(status: number, error: ErrorResponse["error"]) {
		super(error.message);
		this.name = "ApiError";
		this.status = status;
		this.code = error.code;
		this.requestId = error.request_id;
	}
}

export class ApiClient {
	constructor(private readonly baseURL = "/v1") {}

	async request<T>(path: string, options: RequestInit = {}): Promise<T> {
		const res = await fetch(`${this.baseURL}${path}`, {
			credentials: "include",
			headers: {
				"Content-Type": "application/json",
				...(options.headers ?? {}),
			},
			...options,
		});
		if (!res.ok) {
			let body: ErrorResponse = {
				error: { code: "http_error", message: res.statusText },
			};
			try {
				body = await res.json();
			} catch {
				/* keep generic error */
			}
			throw new ApiError(res.status, body.error);
		}
		if (res.status === 204) return undefined as T;
		return res.json() as Promise<T>;
	}

	providers() {
		return this.request<{ items: AuthProvider[] }>("/auth/providers");
	}
	me() {
		return this.request<CurrentUser>("/auth/me");
	}
	localLogin(email: string, password: string) {
		return this.request<CurrentUser>("/auth/local/login", {
			method: "POST",
			body: JSON.stringify({ email, password }),
		});
	}
	logout() {
		return this.request<void>("/auth/logout", { method: "POST" });
	}
	findings(query = "") {
		return this.request<ListResponse<Finding>>(`/findings${query}`);
	}
	packages(query = "") {
		return this.request<ListResponse<PackageSummary>>(`/packages${query}`);
	}
	analyzerRuns(query = "") {
		return this.request<ListResponse<AnalyzerRun>>(`/analyzer-runs${query}`);
	}
	impactPaths(query = "") {
		return this.request<ListResponse<ImpactPath>>(
			`/graph/impact-paths${query}`,
		);
	}
	alerts(query = "") {
		return this.request<ListResponse<Alert>>(`/alerts${query}`);
	}
	notificationRoutes() {
		return this.request<ListResponse<NotificationRoute>>(
			"/notification-routes",
		);
	}
}

export const api = new ApiClient();
