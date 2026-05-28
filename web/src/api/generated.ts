/* Generated from docs/api/openapi.yaml. Do not edit by hand. */
export const apiInfo = {
  "title": "Tallow API",
  "version": "0.1.0"
} as const;
export const apiPaths = [
  "/admin/users",
  "/admin/users/{user_id}/roles",
  "/alerts",
  "/alerts/{alert_id}",
  "/analyzer-runs",
  "/analyzer-runs/{run_id}",
  "/artifacts/{artifact_id}",
  "/artifacts/{id}/source-correlations",
  "/auth/github/callback",
  "/auth/github/login",
  "/auth/local/login",
  "/auth/logout",
  "/auth/me",
  "/auth/providers",
  "/findings",
  "/findings/{finding_id}",
  "/graph/affected-direct-dependencies",
  "/graph/impact-paths",
  "/healthz",
  "/metrics",
  "/notification-deliveries",
  "/notification-routes",
  "/notification-routes/{route_id}",
  "/notification-routes/{route_id}/test",
  "/notification-templates/preview",
  "/observations",
  "/package-versions/{id}/source-correlations",
  "/package-versions/{id}/statuses",
  "/package-versions/{id}/transitive-impacts",
  "/packages",
  "/packages/{package_id}",
  "/packages/{package_id}/versions",
  "/readyz",
  "/settings",
  "/source-correlations",
  "/statuses/{id}/affected-dependents",
  "/versions/{version_id}"
] as const;
export const apiSchemas = [
  "Alert",
  "AlertPage",
  "AlertStatus",
  "AnalyzerRun",
  "AnalyzerRunPage",
  "Artifact",
  "AuthProvider",
  "Confidence",
  "CurrentUser",
  "Ecosystem",
  "ErrorResponse",
  "EvidenceRef",
  "Finding",
  "FindingPage",
  "FindingStatus",
  "ImpactPath",
  "ImpactPathPage",
  "LocalLoginRequest",
  "NotificationDelivery",
  "NotificationDeliveryPage",
  "NotificationRoute",
  "NotificationRoutePage",
  "Observation",
  "ObservationPage",
  "Package",
  "PackagePage",
  "PackageVersion",
  "PackageVersionPage",
  "PageInfo",
  "Role",
  "Session",
  "Settings",
  "Severity",
  "User",
  "UserPage"
] as const;

export type Role = 'admin' | 'analyst' | 'viewer';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high' | 'confirmed' | 'unknown';
export type FindingStatus = 'open' | 'acknowledged' | 'resolved' | 'suppressed' | 'false_positive';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'suppressed' | 'reopened';

export interface ErrorResponse { error: { code: string; message: string; request_id?: string; details?: string } }
export interface PageInfo { limit: number; offset: number; total: number; next_offset?: number }
export interface User { id: string; email: string; display_name?: string; roles: Role[]; status: string }
export interface CurrentUser { user: User; provider?: string; capabilities: string[] }
export interface AuthProvider { name: string; provider?: string; type: 'local' | 'oauth' | 'password'; label?: string; enabled: boolean; login_url?: string }
export interface Finding { id: string; rule_id: string; package_name?: string; version?: string; severity?: Severity; severity_hint?: string; confidence: Confidence | string; status: FindingStatus | string; summary: string; evidence_refs?: EvidenceRef[]; evidence?: EvidenceRef[]; evidence_count?: number; updated_at?: string }
export interface EvidenceRef { type: string; ref: string; path?: string; line?: number; excerpt?: string; excerpt_safe?: boolean; hash?: string }
export interface Alert { id: string; finding_id?: string; status: AlertStatus; severity: Severity; title: string; summary?: string; package_name?: string; version?: string; evidence_refs?: EvidenceRef[] }
export interface PackageSummary { id: string; ecosystem: string; name: string; registry_url?: string }
export interface PackageVersion { id: string; package_id: string; version: string }
export interface AnalyzerRun { id: string; analyzer_id: string; analyzer_version?: string; status: string; started_at?: string; finished_at?: string }
export interface ImpactPath { id: string; finding_id?: string; status: string; path: string[]; evidence_refs?: EvidenceRef[] }
export interface NotificationRoute { id: string; name: string; channel: 'email' | 'teams'; enabled: boolean; secret_configured?: boolean }

export interface ListResponse<T> { items: T[]; page?: PageInfo; next_cursor?: string }
