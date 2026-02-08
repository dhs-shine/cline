import axios from "axios"
import { expect } from "chai"
import { afterEach, beforeEach, describe, it } from "mocha"
import * as sinon from "sinon"
import type { Controller } from "@/core/controller"
import type { StateManager } from "@/core/storage/StateManager"
import type { ClineAuthInfo } from "../../AuthService"
import { KeycloakAuthProvider } from "../KeycloakAuthProvider"
import { clearEndpointsCache, type KeycloakConfig } from "../KeycloakConfig"

describe("KeycloakAuthProvider", () => {
	let sandbox: sinon.SinonSandbox
	let provider: KeycloakAuthProvider
	let mockController: Partial<Controller>
	let storedSecrets: Map<string, string | undefined>

	const testConfig: KeycloakConfig = {
		serverUrl: "https://auth.test.com",
		realm: "test-realm",
		clientId: "test-client",
		scopes: "openid profile email offline_access",
	}

	beforeEach(() => {
		sandbox = sinon.createSandbox()
		clearEndpointsCache()

		storedSecrets = new Map()

		mockController = {
			stateManager: {
				getSecretKey: (key: string) => storedSecrets.get(key),
				setSecret: (key: string, value: string | undefined) => {
					if (value === undefined) {
						storedSecrets.delete(key)
					} else {
						storedSecrets.set(key, value)
					}
				},
			} as Partial<StateManager> as StateManager,
		}

		provider = new KeycloakAuthProvider(testConfig)
	})

	afterEach(() => {
		sandbox.restore()
		clearEndpointsCache()
	})

	describe("name", () => {
		it("should return 'keycloak'", () => {
			expect(provider.name).to.equal("keycloak")
		})
	})

	describe("getAuthRequest", () => {
		it("should generate valid authorization URL with PKCE parameters", async () => {
			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/realms/test-realm/protocol/openid-connect/auth",
					token_endpoint: "https://auth.test.com/realms/test-realm/protocol/openid-connect/token",
					userinfo_endpoint: "https://auth.test.com/realms/test-realm/protocol/openid-connect/userinfo",
					end_session_endpoint: "https://auth.test.com/realms/test-realm/protocol/openid-connect/logout",
				},
			}
			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const callbackUrl = "vscode://saoudrizwan.claude-dev/auth"
			const authUrl = await provider.getAuthRequest(callbackUrl)

			const url = new URL(authUrl)

			expect(url.origin + url.pathname).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/auth")
			expect(url.searchParams.get("client_id")).to.equal("test-client")
			expect(url.searchParams.get("response_type")).to.equal("code")
			expect(url.searchParams.get("scope")).to.equal("openid profile email offline_access")
			expect(url.searchParams.get("redirect_uri")).to.equal(callbackUrl)
			expect(url.searchParams.get("code_challenge_method")).to.equal("S256")

			expect(url.searchParams.get("state")).to.be.a("string").and.have.length.greaterThan(10)
			expect(url.searchParams.get("nonce")).to.be.a("string").and.have.length.greaterThan(10)
			expect(url.searchParams.get("code_challenge")).to.be.a("string").and.have.length.greaterThan(10)
		})

		it("should generate unique state and nonce for each request", async () => {
			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/auth",
					token_endpoint: "https://auth.test.com/token",
					userinfo_endpoint: "https://auth.test.com/userinfo",
					end_session_endpoint: "https://auth.test.com/logout",
				},
			}
			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const url1 = new URL(await provider.getAuthRequest("http://callback1"))
			const url2 = new URL(await provider.getAuthRequest("http://callback2"))

			expect(url1.searchParams.get("state")).to.not.equal(url2.searchParams.get("state"))
			expect(url1.searchParams.get("nonce")).to.not.equal(url2.searchParams.get("nonce"))
		})
	})

	describe("signIn", () => {
		it("should reject invalid state", async () => {
			try {
				await provider.signIn(mockController as Controller, "auth-code", "invalid-state")
				expect.fail("Should have thrown an error")
			} catch (error: unknown) {
				expect((error as Error).message).to.include("Invalid or expired PKCE state")
			}
		})

		it("should exchange code for tokens and store auth info", async () => {
			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/auth",
					token_endpoint: "https://auth.test.com/token",
					userinfo_endpoint: "https://auth.test.com/userinfo",
					end_session_endpoint: "https://auth.test.com/logout",
				},
			}

			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const authUrl = await provider.getAuthRequest("http://callback")
			const url = new URL(authUrl)
			const state = url.searchParams.get("state") ?? ""
			const nonce = url.searchParams.get("nonce") ?? ""

			const mockIdToken = createMockJwt({ sub: "user-123", email: "test@example.com", name: "Test User", nonce })

			const tokenResponse = {
				data: {
					access_token: "mock-access-token",
					refresh_token: "mock-refresh-token",
					id_token: mockIdToken,
					expires_in: 300,
					token_type: "Bearer",
				},
			}

			const axiosPostStub = sandbox.stub(axios, "post").resolves(tokenResponse)

			const authInfo = await provider.signIn(mockController as Controller, "auth-code", state)

			expect(authInfo).to.not.be.null
			expect(authInfo?.idToken).to.equal("mock-access-token")
			expect(authInfo?.refreshToken).to.equal("mock-refresh-token")
			expect(authInfo?.provider).to.equal("keycloak")
			expect(authInfo?.userInfo.id).to.equal("user-123")
			expect(authInfo?.userInfo.email).to.equal("test@example.com")
			expect(authInfo?.userInfo.displayName).to.equal("Test User")

			expect(axiosPostStub.calledOnce).to.be.true
			const postCall = axiosPostStub.firstCall
			expect(postCall.args[0]).to.equal("https://auth.test.com/token")
			expect(postCall.args[1]).to.include("grant_type=authorization_code")
			expect(postCall.args[1]).to.include("code=auth-code")
			expect(postCall.args[1]).to.include("code_verifier=")
		})

		it("should reject mismatched nonce", async () => {
			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/auth",
					token_endpoint: "https://auth.test.com/token",
					userinfo_endpoint: "https://auth.test.com/userinfo",
					end_session_endpoint: "https://auth.test.com/logout",
				},
			}

			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const authUrl = await provider.getAuthRequest("http://callback")
			const url = new URL(authUrl)
			const state = url.searchParams.get("state") ?? ""

			const mockIdToken = createMockJwt({ sub: "user-123", nonce: "wrong-nonce" })

			const tokenResponse = {
				data: {
					access_token: "mock-access-token",
					refresh_token: "mock-refresh-token",
					id_token: mockIdToken,
					expires_in: 300,
				},
			}

			sandbox.stub(axios, "post").resolves(tokenResponse)

			try {
				await provider.signIn(mockController as Controller, "auth-code", state)
				expect.fail("Should have thrown an error")
			} catch (error: unknown) {
				expect((error as Error).message).to.include("Nonce verification failed")
			}
		})
	})

	describe("refreshToken", () => {
		it("should refresh tokens successfully", async () => {
			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/auth",
					token_endpoint: "https://auth.test.com/token",
					userinfo_endpoint: "https://auth.test.com/userinfo",
					end_session_endpoint: "https://auth.test.com/logout",
				},
			}

			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const mockIdToken = createMockJwt({ sub: "user-123", email: "refreshed@example.com", name: "Refreshed User" })

			const tokenResponse = {
				data: {
					access_token: "new-access-token",
					refresh_token: "new-refresh-token",
					id_token: mockIdToken,
					expires_in: 300,
				},
			}

			sandbox.stub(axios, "post").resolves(tokenResponse)

			const storedData: ClineAuthInfo = {
				idToken: "old-access-token",
				refreshToken: "old-refresh-token",
				provider: "keycloak",
				userInfo: {
					id: "user-123",
					email: "old@example.com",
					displayName: "Old User",
					createdAt: new Date().toISOString(),
					organizations: [],
				},
				startedAt: Date.now() - 10000,
			}

			const authInfo = await provider.refreshToken("old-refresh-token", storedData)

			expect(authInfo.idToken).to.equal("new-access-token")
			expect(authInfo.refreshToken).to.equal("new-refresh-token")
			expect(authInfo.startedAt).to.equal(storedData.startedAt)
		})

		it("should throw AuthInvalidTokenError on invalid_grant", async () => {
			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/auth",
					token_endpoint: "https://auth.test.com/token",
					userinfo_endpoint: "https://auth.test.com/userinfo",
					end_session_endpoint: "https://auth.test.com/logout",
				},
			}

			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const axiosError = {
				isAxiosError: true,
				response: {
					status: 400,
					data: { error: "invalid_grant", error_description: "Token expired" },
				},
			}

			sandbox.stub(axios, "post").rejects(axiosError)
			sandbox.stub(axios, "isAxiosError").returns(true)

			const storedData: ClineAuthInfo = {
				idToken: "old-access-token",
				refreshToken: "expired-refresh-token",
				provider: "keycloak",
				userInfo: {
					id: "user-123",
					email: "test@example.com",
					displayName: "Test",
					createdAt: new Date().toISOString(),
					organizations: [],
				},
			}

			try {
				await provider.refreshToken("expired-refresh-token", storedData)
				expect.fail("Should have thrown an error")
			} catch (error: unknown) {
				expect((error as Error).name).to.equal("AuthInvalidTokenError")
			}
		})
	})

	describe("shouldRefreshIdToken", () => {
		it("should return true when token is expired", async () => {
			const pastTime = Date.now() / 1000 - 100

			const result = await provider.shouldRefreshIdToken("any-token", pastTime)

			expect(result).to.be.true
		})

		it("should return true when token expires within 5 minutes", async () => {
			const soonTime = Date.now() / 1000 + 60

			const result = await provider.shouldRefreshIdToken("any-token", soonTime)

			expect(result).to.be.true
		})

		it("should return false when token has more than 5 minutes left", async () => {
			const futureTime = Date.now() / 1000 + 600

			const result = await provider.shouldRefreshIdToken("any-token", futureTime)

			expect(result).to.be.false
		})
	})

	describe("timeUntilExpiry", () => {
		it("should return positive seconds for valid future token", () => {
			const futureExp = Math.floor(Date.now() / 1000) + 300
			const token = createMockJwt({ exp: futureExp })

			const result = provider.timeUntilExpiry(token)

			expect(result).to.be.greaterThan(290)
			expect(result).to.be.lessThanOrEqual(300)
		})

		it("should return negative seconds for expired token", () => {
			const pastExp = Math.floor(Date.now() / 1000) - 100
			const token = createMockJwt({ exp: pastExp })

			const result = provider.timeUntilExpiry(token)

			expect(result).to.be.lessThan(0)
		})

		it("should return 0 for token without exp claim", () => {
			const token = createMockJwt({ sub: "user-123" })

			const result = provider.timeUntilExpiry(token)

			expect(result).to.equal(0)
		})
	})

	describe("retrieveClineAuthInfo", () => {
		it("should return null when no stored auth data", async () => {
			const result = await provider.retrieveClineAuthInfo(mockController as Controller)

			expect(result).to.be.null
		})

		it("should return stored auth data when valid and not expired", async () => {
			const futureExp = Date.now() / 1000 + 600

			const storedAuthInfo: ClineAuthInfo = {
				idToken: "valid-token",
				refreshToken: "refresh-token",
				expiresAt: futureExp,
				provider: "keycloak",
				userInfo: {
					id: "user-123",
					email: "test@example.com",
					displayName: "Test User",
					createdAt: new Date().toISOString(),
					organizations: [],
				},
			}

			storedSecrets.set("keycloak:clineAccountId", JSON.stringify(storedAuthInfo))

			const result = await provider.retrieveClineAuthInfo(mockController as Controller)

			expect(result).to.deep.equal(storedAuthInfo)
		})

		it("should refresh token when expired", async () => {
			const pastExp = Date.now() / 1000 - 100

			const storedAuthInfo: ClineAuthInfo = {
				idToken: "expired-token",
				refreshToken: "valid-refresh-token",
				expiresAt: pastExp,
				provider: "keycloak",
				userInfo: {
					id: "user-123",
					email: "test@example.com",
					displayName: "Test User",
					createdAt: new Date().toISOString(),
					organizations: [],
				},
			}

			storedSecrets.set("keycloak:clineAccountId", JSON.stringify(storedAuthInfo))

			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/auth",
					token_endpoint: "https://auth.test.com/token",
					userinfo_endpoint: "https://auth.test.com/userinfo",
					end_session_endpoint: "https://auth.test.com/logout",
				},
			}

			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const mockIdToken = createMockJwt({ sub: "user-123", email: "test@example.com", name: "Test User" })

			const tokenResponse = {
				data: {
					access_token: "new-access-token",
					refresh_token: "new-refresh-token",
					id_token: mockIdToken,
					expires_in: 300,
				},
			}

			sandbox.stub(axios, "post").resolves(tokenResponse)

			const result = await provider.retrieveClineAuthInfo(mockController as Controller)

			expect(result).to.not.be.null
			expect(result?.idToken).to.equal("new-access-token")
		})
	})
})

function createMockJwt(payload: Record<string, unknown>): string {
	const header = { alg: "RS256", typ: "JWT" }
	const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url")
	const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url")
	const signature = "mock-signature"

	return `${encodedHeader}.${encodedPayload}.${signature}`
}
