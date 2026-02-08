import { expect } from "chai"
import crypto from "crypto"
import { describe, it } from "mocha"
import { generateCodeVerifier, generateRandomString, parseJwtPayload, pkceChallengeFromVerifier } from "../utils"

describe("PKCE Utilities", () => {
	describe("generateRandomString", () => {
		it("should generate string of specified length", () => {
			const result = generateRandomString(32)

			expect(result).to.have.length(32)
		})

		it("should generate different strings each time", () => {
			const result1 = generateRandomString(32)
			const result2 = generateRandomString(32)

			expect(result1).to.not.equal(result2)
		})

		it("should only contain valid characters", () => {
			const validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
			const result = generateRandomString(100)

			for (const char of result) {
				expect(validChars).to.include(char)
			}
		})

		it("should use custom character set when provided", () => {
			const customChars = "ABC"
			const result = generateRandomString(50, customChars)

			for (const char of result) {
				expect(customChars).to.include(char)
			}
		})
	})

	describe("generateCodeVerifier", () => {
		it("should generate verifier of default length (128)", () => {
			const result = generateCodeVerifier()

			expect(result).to.have.length(128)
		})

		it("should generate verifier of custom length", () => {
			const result = generateCodeVerifier(64)

			expect(result).to.have.length(64)
		})

		it("should only contain RFC 7636 unreserved characters", () => {
			const validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
			const result = generateCodeVerifier()

			for (const char of result) {
				expect(validChars).to.include(char)
			}
		})

		it("should generate different verifiers each time", () => {
			const result1 = generateCodeVerifier()
			const result2 = generateCodeVerifier()

			expect(result1).to.not.equal(result2)
		})

		it("should meet PKCE length requirements (43-128 chars)", () => {
			const minResult = generateCodeVerifier(43)
			const maxResult = generateCodeVerifier(128)

			expect(minResult.length).to.be.at.least(43)
			expect(maxResult.length).to.be.at.most(128)
		})
	})

	describe("pkceChallengeFromVerifier", () => {
		it("should generate base64url-encoded SHA-256 hash", () => {
			const verifier = "test-verifier-string"
			const result = pkceChallengeFromVerifier(verifier)

			expect(result).to.be.a("string")
			expect(result.length).to.be.greaterThan(0)
		})

		it("should not contain + / = characters (base64url)", () => {
			const verifier = generateCodeVerifier()
			const result = pkceChallengeFromVerifier(verifier)

			expect(result).to.not.include("+")
			expect(result).to.not.include("/")
			expect(result).to.not.include("=")
		})

		it("should produce consistent output for same input", () => {
			const verifier = "consistent-verifier"
			const result1 = pkceChallengeFromVerifier(verifier)
			const result2 = pkceChallengeFromVerifier(verifier)

			expect(result1).to.equal(result2)
		})

		it("should produce different output for different input", () => {
			const result1 = pkceChallengeFromVerifier("verifier-one")
			const result2 = pkceChallengeFromVerifier("verifier-two")

			expect(result1).to.not.equal(result2)
		})

		it("should match expected SHA-256 hash", () => {
			const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

			const expectedHash = crypto.createHash("sha256").update(verifier).digest("base64url")

			const result = pkceChallengeFromVerifier(verifier)

			expect(result).to.equal(expectedHash)
		})

		it("should produce 43-character challenge for standard verifier", () => {
			const verifier = generateCodeVerifier()
			const result = pkceChallengeFromVerifier(verifier)

			expect(result.length).to.equal(43)
		})
	})

	describe("parseJwtPayload", () => {
		it("should parse valid JWT payload", () => {
			const payload = { sub: "user-123", email: "test@example.com", exp: 1234567890 }
			const token = createMockJwt(payload)

			const result = parseJwtPayload<typeof payload>(token)

			expect(result).to.deep.include(payload)
		})

		it("should return null for invalid JWT", () => {
			const result = parseJwtPayload("not-a-jwt")

			expect(result).to.be.null
		})

		it("should return null for JWT with invalid base64", () => {
			const result = parseJwtPayload("header.!!!invalid!!!.signature")

			expect(result).to.be.null
		})

		it("should return null for empty string", () => {
			const result = parseJwtPayload("")

			expect(result).to.be.null
		})

		it("should handle JWT with complex nested payload", () => {
			const payload = {
				sub: "user-123",
				"https://custom.claim": {
					nested: {
						value: "deep-value",
					},
				},
				roles: ["admin", "user"],
			}
			const token = createMockJwt(payload)

			const result = parseJwtPayload<typeof payload>(token)

			expect(result).to.deep.include(payload)
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
