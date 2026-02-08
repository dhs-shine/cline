import axios from "axios"
import { Controller } from "@/core/controller"
import { AuthInvalidTokenError, AuthNetworkError } from "@/services/error/ClineError"
import { getAxiosSettings } from "@/shared/net"
import { Logger } from "@/shared/services/Logger"
import { ClineAuthInfo, ClineAccountUserInfo } from "../AuthService"
import { generateCodeVerifier, generateRandomString, pkceChallengeFromVerifier } from "../oca/utils/utils"
import { parseJwtPayload } from "../oca/utils/utils"
import { AuthProvider, PkceState } from "../types"
import { KeycloakConfig, discoverKeycloakEndpoints, KeycloakEndpoints } from "./KeycloakConfig"

const PKCE_STATE_TTL_MS = 10 * 60 * 1000
const STORAGE_KEY = "keycloak:clineAccountId"

export class KeycloakAuthProvider implements AuthProvider {
	readonly name = "keycloak"
	private static pkceStateMap: Map<string, PkceState> = new Map()
	private endpoints: KeycloakEndpoints | null = null

	constructor(private config: KeycloakConfig) {}

	private async getEndpoints(): Promise<KeycloakEndpoints> {
		if (!this.endpoints) {
			this.endpoints = await discoverKeycloakEndpoints(this.config)
		}
		return this.endpoints
	}

	private cleanupExpiredPkceStates(): void {
		const cutoff = Date.now() - PKCE_STATE_TTL_MS
		for (const [key, entry] of KeycloakAuthProvider.pkceStateMap.entries()) {
			if (entry.createdAt < cutoff) {
				KeycloakAuthProvider.pkceStateMap.delete(key)
			}
		}
	}

	async getAuthRequest(callbackUrl: string): Promise<string> {
		const endpoints = await this.getEndpoints()

		const code_verifier = generateCodeVerifier()
		const code_challenge = pkceChallengeFromVerifier(code_verifier)
		const state = generateRandomString(32)
		const nonce = generateRandomString(32)

		this.cleanupExpiredPkceStates()

		KeycloakAuthProvider.pkceStateMap.set(state, {
			code_verifier,
			nonce,
			createdAt: Date.now(),
			redirect_uri: callbackUrl,
		})

		const url = new URL(endpoints.authorization)
		url.searchParams.set("client_id", this.config.clientId)
		url.searchParams.set("response_type", "code")
		url.searchParams.set("scope", this.config.scopes)
		url.searchParams.set("redirect_uri", callbackUrl)
		url.searchParams.set("state", state)
		url.searchParams.set("nonce", nonce)
		url.searchParams.set("code_challenge", code_challenge)
		url.searchParams.set("code_challenge_method", "S256")

		return url.toString()
	}

	async signIn(controller: Controller, code: string, state: string): Promise<ClineAuthInfo | null> {
		const entry = KeycloakAuthProvider.pkceStateMap.get(state)
		if (!entry) {
			throw new Error("Invalid or expired PKCE state")
		}

		const isExpired = Date.now() - entry.createdAt > PKCE_STATE_TTL_MS
		if (isExpired) {
			KeycloakAuthProvider.pkceStateMap.delete(state)
			throw new Error("PKCE state expired")
		}

		KeycloakAuthProvider.pkceStateMap.delete(state)

		const endpoints = await this.getEndpoints()

		const params = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: entry.redirect_uri,
			client_id: this.config.clientId,
			code_verifier: entry.code_verifier,
		})

		try {
			const response = await axios.post(endpoints.token, params.toString(), {
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				...getAxiosSettings(),
			})

			const tokens = response.data

			const idTokenPayload = parseJwtPayload<{ nonce?: string }>(tokens.id_token)
			if (idTokenPayload?.nonce !== entry.nonce) {
				throw new Error("Nonce verification failed")
			}

			const authInfo = this.buildAuthInfo(tokens)
			controller.stateManager.setSecret(STORAGE_KEY, JSON.stringify(authInfo))

			return authInfo
		} catch (error: any) {
			if (axios.isAxiosError(error)) {
				const status = error.response?.status
				const data = error.response?.data
				Logger.error("Keycloak token exchange failed:", { status, data })
				throw new Error(`Token exchange failed: ${data?.error_description || data?.error || error.message}`)
			}
			throw error
		}
	}

	async refreshToken(refreshToken: string, storedData: ClineAuthInfo): Promise<ClineAuthInfo> {
		const endpoints = await this.getEndpoints()

		const params = new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
			client_id: this.config.clientId,
		})

		try {
			const response = await axios.post(endpoints.token, params.toString(), {
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				...getAxiosSettings(),
			})

			return this.buildAuthInfo(response.data, storedData.startedAt)
		} catch (error: any) {
			if (axios.isAxiosError(error)) {
				const status = error.response?.status
				const data = error.response?.data

				if (status === 400 || status === 401) {
					const errorCode = data?.error
					if (errorCode === "invalid_grant" || errorCode === "invalid_token") {
						throw new AuthInvalidTokenError("Refresh token expired or revoked")
					}
				}

				throw new AuthNetworkError(`Token refresh failed: ${status}`, data)
			}
			throw error
		}
	}

	async shouldRefreshIdToken(_refreshToken: string, expiresAt?: number): Promise<boolean> {
		const expirationTime = expiresAt || 0
		const currentTime = Date.now() / 1000
		const fiveMinutesFromNow = currentTime + 5 * 60

		return expirationTime < fiveMinutesFromNow
	}

	timeUntilExpiry(jwt: string): number {
		const payload = parseJwtPayload<{ exp?: number }>(jwt)
		if (!payload?.exp) {
			return 0
		}

		const currentTime = Date.now() / 1000
		return payload.exp - currentTime
	}

	async retrieveClineAuthInfo(controller: Controller): Promise<ClineAuthInfo | null> {
		const storedAuthDataString = controller.stateManager.getSecretKey(STORAGE_KEY)

		if (!storedAuthDataString) {
			return null
		}

		let storedAuthData: ClineAuthInfo
		try {
			storedAuthData = JSON.parse(storedAuthDataString)
		} catch {
			Logger.error("Failed to parse stored Keycloak auth data")
			controller.stateManager.setSecret(STORAGE_KEY, undefined)
			return null
		}

		if (!storedAuthData.refreshToken || !storedAuthData.idToken) {
			controller.stateManager.setSecret(STORAGE_KEY, undefined)
			return null
		}

		if (await this.shouldRefreshIdToken(storedAuthData.refreshToken, storedAuthData.expiresAt)) {
			try {
				const refreshedAuthInfo = await this.refreshToken(storedAuthData.refreshToken, storedAuthData)
				controller.stateManager.setSecret(STORAGE_KEY, JSON.stringify(refreshedAuthInfo))
				return refreshedAuthInfo
			} catch (error) {
				if (error instanceof AuthInvalidTokenError) {
					Logger.error("Keycloak refresh token invalid, clearing auth state")
					controller.stateManager.setSecret(STORAGE_KEY, undefined)
					throw error
				}
				Logger.warn("Keycloak token refresh failed, returning stale data:", error)
				return storedAuthData
			}
		}

		return storedAuthData
	}

	private buildAuthInfo(tokens: any, startedAt?: number): ClineAuthInfo {
		interface KeycloakIdTokenPayload {
			sub?: string
			email?: string
			name?: string
			preferred_username?: string
			given_name?: string
			family_name?: string
		}

		const idTokenPayload = parseJwtPayload<KeycloakIdTokenPayload>(tokens.id_token)

		const displayName =
			idTokenPayload?.name ||
			idTokenPayload?.preferred_username ||
			[idTokenPayload?.given_name, idTokenPayload?.family_name].filter(Boolean).join(" ") ||
			""

		const userInfo: ClineAccountUserInfo = {
			id: idTokenPayload?.sub || "",
			email: idTokenPayload?.email || "",
			displayName,
			createdAt: new Date().toISOString(),
			organizations: [],
		}

		return {
			idToken: tokens.access_token,
			refreshToken: tokens.refresh_token,
			expiresAt: Date.now() / 1000 + (tokens.expires_in || 300),
			provider: this.name,
			startedAt: startedAt || Date.now(),
			userInfo,
		}
	}
}
