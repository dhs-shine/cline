import fs from "fs"
import path from "path"
import os from "os"
import axios from "axios"
import { getAxiosSettings } from "@/shared/net"
import { Logger } from "@/shared/services/Logger"

export interface KeycloakConfig {
	serverUrl: string
	realm: string
	clientId: string
	scopes: string
}

export interface KeycloakEndpoints {
	authorization: string
	token: string
	userinfo: string
	logout: string
}

const DEFAULT_SCOPES = "openid profile email offline_access"
const KEYCLOAK_CONFIG_PATH = path.join(os.homedir(), ".cline", "keycloak.json")

export function loadKeycloakConfig(): KeycloakConfig {
	let cfg: Partial<KeycloakConfig> = {}

	try {
		const raw = fs.readFileSync(KEYCLOAK_CONFIG_PATH, "utf-8")
		cfg = JSON.parse(raw)
	} catch {
		// Config file not found or invalid, use env vars
	}

	const serverUrl = cfg.serverUrl || process.env.KEYCLOAK_SERVER_URL
	const realm = cfg.realm || process.env.KEYCLOAK_REALM
	const clientId = cfg.clientId || process.env.KEYCLOAK_CLIENT_ID

	if (!serverUrl || !realm || !clientId) {
		throw new Error(
			"Keycloak configuration incomplete. Set KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID " +
				`or create ${KEYCLOAK_CONFIG_PATH}`,
		)
	}

	return {
		serverUrl: serverUrl.replace(/\/$/, ""),
		realm,
		clientId,
		scopes: cfg.scopes || process.env.KEYCLOAK_SCOPES || DEFAULT_SCOPES,
	}
}

export function buildKeycloakEndpoints(config: KeycloakConfig): KeycloakEndpoints {
	const base = `${config.serverUrl}/realms/${config.realm}/protocol/openid-connect`
	return {
		authorization: `${base}/auth`,
		token: `${base}/token`,
		userinfo: `${base}/userinfo`,
		logout: `${base}/logout`,
	}
}

let cachedEndpoints: KeycloakEndpoints | null = null

export async function discoverKeycloakEndpoints(config: KeycloakConfig): Promise<KeycloakEndpoints> {
	if (cachedEndpoints) {
		return cachedEndpoints
	}

	const wellKnownUrl = `${config.serverUrl}/realms/${config.realm}/.well-known/openid-configuration`

	try {
		const response = await axios.get(wellKnownUrl, {
			timeout: 10000,
			...getAxiosSettings(),
		})

		const discovery = response.data
		cachedEndpoints = {
			authorization: discovery.authorization_endpoint,
			token: discovery.token_endpoint,
			userinfo: discovery.userinfo_endpoint,
			logout: discovery.end_session_endpoint,
		}

		return cachedEndpoints
	} catch (error) {
		Logger.warn("Keycloak discovery failed, using hardcoded endpoints:", error)
		return buildKeycloakEndpoints(config)
	}
}

export function clearEndpointsCache(): void {
	cachedEndpoints = null
}
