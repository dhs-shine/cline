import axios from "axios"
import { expect } from "chai"
import * as fs from "fs"
import { afterEach, beforeEach, describe, it } from "mocha"
import * as sinon from "sinon"
import {
	buildKeycloakEndpoints,
	clearEndpointsCache,
	discoverKeycloakEndpoints,
	type KeycloakConfig,
	loadKeycloakConfig,
} from "../KeycloakConfig"

describe("KeycloakConfig", () => {
	let sandbox: sinon.SinonSandbox
	let originalEnv: NodeJS.ProcessEnv

	beforeEach(() => {
		sandbox = sinon.createSandbox()
		originalEnv = { ...process.env }
		clearEndpointsCache()
	})

	afterEach(() => {
		sandbox.restore()
		process.env = originalEnv
		clearEndpointsCache()
	})

	describe("loadKeycloakConfig", () => {
		it("should load config from environment variables", () => {
			process.env.KEYCLOAK_SERVER_URL = "https://auth.test.com"
			process.env.KEYCLOAK_REALM = "test-realm"
			process.env.KEYCLOAK_CLIENT_ID = "test-client"

			sandbox.stub(fs, "readFileSync").throws(new Error("File not found"))

			const config = loadKeycloakConfig()

			expect(config.serverUrl).to.equal("https://auth.test.com")
			expect(config.realm).to.equal("test-realm")
			expect(config.clientId).to.equal("test-client")
			expect(config.scopes).to.equal("openid profile email offline_access")
		})

		it("should strip trailing slash from serverUrl", () => {
			process.env.KEYCLOAK_SERVER_URL = "https://auth.test.com/"
			process.env.KEYCLOAK_REALM = "test-realm"
			process.env.KEYCLOAK_CLIENT_ID = "test-client"

			sandbox.stub(fs, "readFileSync").throws(new Error("File not found"))

			const config = loadKeycloakConfig()

			expect(config.serverUrl).to.equal("https://auth.test.com")
		})

		it("should use custom scopes from environment", () => {
			process.env.KEYCLOAK_SERVER_URL = "https://auth.test.com"
			process.env.KEYCLOAK_REALM = "test-realm"
			process.env.KEYCLOAK_CLIENT_ID = "test-client"
			process.env.KEYCLOAK_SCOPES = "openid custom_scope"

			sandbox.stub(fs, "readFileSync").throws(new Error("File not found"))

			const config = loadKeycloakConfig()

			expect(config.scopes).to.equal("openid custom_scope")
		})

		it("should load config from JSON file", () => {
			delete process.env.KEYCLOAK_SERVER_URL
			delete process.env.KEYCLOAK_REALM
			delete process.env.KEYCLOAK_CLIENT_ID

			const fileConfig = JSON.stringify({
				serverUrl: "https://file-auth.test.com",
				realm: "file-realm",
				clientId: "file-client",
				scopes: "openid file_scope",
			})

			sandbox.stub(fs, "readFileSync").returns(fileConfig)

			const config = loadKeycloakConfig()

			expect(config.serverUrl).to.equal("https://file-auth.test.com")
			expect(config.realm).to.equal("file-realm")
			expect(config.clientId).to.equal("file-client")
			expect(config.scopes).to.equal("openid file_scope")
		})

		it("should throw error when config is incomplete", () => {
			delete process.env.KEYCLOAK_SERVER_URL
			delete process.env.KEYCLOAK_REALM
			delete process.env.KEYCLOAK_CLIENT_ID

			sandbox.stub(fs, "readFileSync").throws(new Error("File not found"))

			expect(() => loadKeycloakConfig()).to.throw("Keycloak configuration incomplete")
		})

		it("should prefer file config over environment variables for matching fields", () => {
			process.env.KEYCLOAK_SERVER_URL = "https://env-auth.test.com"
			process.env.KEYCLOAK_REALM = "env-realm"
			process.env.KEYCLOAK_CLIENT_ID = "env-client"

			const fileConfig = JSON.stringify({
				serverUrl: "https://file-auth.test.com",
				realm: "file-realm",
				clientId: "file-client",
			})

			sandbox.stub(fs, "readFileSync").returns(fileConfig)

			const config = loadKeycloakConfig()

			expect(config.serverUrl).to.equal("https://file-auth.test.com")
			expect(config.realm).to.equal("file-realm")
			expect(config.clientId).to.equal("file-client")
		})
	})

	describe("buildKeycloakEndpoints", () => {
		it("should build correct OIDC endpoints", () => {
			const config: KeycloakConfig = {
				serverUrl: "https://auth.test.com",
				realm: "test-realm",
				clientId: "test-client",
				scopes: "openid",
			}

			const endpoints = buildKeycloakEndpoints(config)

			expect(endpoints.authorization).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/auth")
			expect(endpoints.token).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/token")
			expect(endpoints.userinfo).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/userinfo")
			expect(endpoints.logout).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/logout")
		})
	})

	describe("discoverKeycloakEndpoints", () => {
		it("should fetch endpoints from well-known configuration", async () => {
			const config: KeycloakConfig = {
				serverUrl: "https://auth.test.com",
				realm: "test-realm",
				clientId: "test-client",
				scopes: "openid",
			}

			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/custom/auth",
					token_endpoint: "https://auth.test.com/custom/token",
					userinfo_endpoint: "https://auth.test.com/custom/userinfo",
					end_session_endpoint: "https://auth.test.com/custom/logout",
				},
			}

			sandbox.stub(axios, "get").resolves(discoveryResponse)

			const endpoints = await discoverKeycloakEndpoints(config)

			expect(endpoints.authorization).to.equal("https://auth.test.com/custom/auth")
			expect(endpoints.token).to.equal("https://auth.test.com/custom/token")
			expect(endpoints.userinfo).to.equal("https://auth.test.com/custom/userinfo")
			expect(endpoints.logout).to.equal("https://auth.test.com/custom/logout")
		})

		it("should cache discovery results", async () => {
			const config: KeycloakConfig = {
				serverUrl: "https://auth.test.com",
				realm: "test-realm",
				clientId: "test-client",
				scopes: "openid",
			}

			const discoveryResponse = {
				data: {
					authorization_endpoint: "https://auth.test.com/custom/auth",
					token_endpoint: "https://auth.test.com/custom/token",
					userinfo_endpoint: "https://auth.test.com/custom/userinfo",
					end_session_endpoint: "https://auth.test.com/custom/logout",
				},
			}

			const axiosStub = sandbox.stub(axios, "get").resolves(discoveryResponse)

			await discoverKeycloakEndpoints(config)
			await discoverKeycloakEndpoints(config)

			expect(axiosStub.calledOnce).to.be.true
		})

		it("should fallback to hardcoded endpoints on discovery failure", async () => {
			const config: KeycloakConfig = {
				serverUrl: "https://auth.test.com",
				realm: "test-realm",
				clientId: "test-client",
				scopes: "openid",
			}

			sandbox.stub(axios, "get").rejects(new Error("Network error"))

			const endpoints = await discoverKeycloakEndpoints(config)

			expect(endpoints.authorization).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/auth")
			expect(endpoints.token).to.equal("https://auth.test.com/realms/test-realm/protocol/openid-connect/token")
		})
	})
})
