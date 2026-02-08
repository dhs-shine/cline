import type { Controller } from "@/core/controller"
import type { ClineAuthInfo } from "./AuthService"

/**
 * Enum defining different reasons why a user might be logged out
 * Used for telemetry tracking to understand logout patterns
 */
export enum LogoutReason {
	/** User explicitly clicked logout button in UI */
	USER_INITIATED = "user_initiated",
	/** Auth tokens were cleared in another VSCode window (cross-window sync) */
	CROSS_WINDOW_SYNC = "cross_window_sync",
	/** Auth provider encountered an error and cleared tokens */
	ERROR_RECOVERY = "error_recovery",
	/** Unknown or unspecified reason */
	UNKNOWN = "unknown",
}

/**
 * Common interface for authentication providers.
 * Implemented by ClineAuthProvider, KeycloakAuthProvider, etc.
 */
export interface AuthProvider {
	/** Provider identifier (e.g., "cline", "keycloak") */
	readonly name: string

	/**
	 * Generates the authorization URL for initiating the OAuth flow.
	 * @param callbackUrl - The callback URL to redirect after authentication
	 * @returns The full authorization URL to open in browser
	 */
	getAuthRequest(callbackUrl: string): Promise<string>

	/**
	 * Exchanges authorization code for tokens and creates auth session.
	 * @param controller - Controller instance for state management
	 * @param authorizationCode - The authorization code from OAuth callback
	 * @param provider - Provider identifier (for multi-provider scenarios)
	 * @returns Auth info on success, null on failure
	 */
	signIn(controller: Controller, authorizationCode: string, provider: string): Promise<ClineAuthInfo | null>

	/**
	 * Refreshes the access token using the refresh token.
	 * @param refreshToken - The refresh token
	 * @param storedData - Previously stored auth info
	 * @returns Updated auth info with new tokens
	 */
	refreshToken(refreshToken: string, storedData: ClineAuthInfo): Promise<ClineAuthInfo>

	/**
	 * Checks if the access token needs to be refreshed.
	 * @param refreshToken - The existing refresh token
	 * @param expiresAt - Token expiration time in seconds since epoch
	 * @returns True if token should be refreshed
	 */
	shouldRefreshIdToken(refreshToken: string, expiresAt?: number): Promise<boolean>

	/**
	 * Returns the time in seconds until token expiry.
	 * @param jwt - The JWT token to check
	 * @returns Seconds until expiry (negative if expired)
	 */
	timeUntilExpiry(jwt: string): number

	/**
	 * Retrieves and validates stored authentication info.
	 * Handles token refresh if needed.
	 * @param controller - Controller instance for state management
	 * @returns Stored auth info or null if not authenticated
	 */
	retrieveClineAuthInfo(controller: Controller): Promise<ClineAuthInfo | null>
}

/**
 * PKCE state stored during authorization flow.
 * Used to correlate authorization callback with original request.
 */
export interface PkceState {
	/** PKCE code verifier (high entropy random string) */
	code_verifier: string
	/** Nonce for replay attack prevention */
	nonce: string
	/** Timestamp when state was created (for expiry) */
	createdAt: number
	/** Redirect URI used in the authorization request */
	redirect_uri: string
}
