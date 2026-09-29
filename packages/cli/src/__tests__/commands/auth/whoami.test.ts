import {
	mockConsoleMethods,
	runInTempDir,
} from "@cloudflare/workers-utils/test-helpers";
import { http, HttpResponse } from "msw";
import { getGlobalDispatcher, MockAgent, setGlobalDispatcher } from "undici";
import { describe, expect, it } from "vitest";
import { server, setupMsw, TEST_BASE_URL } from "../../helpers/msw.js";
import { runCf } from "../../helpers/run-cf.js";

describe("cf auth whoami", () => {
	runInTempDir();
	setupMsw();
	const std = mockConsoleMethods();

	it("outputs the accounts the active credentials are authorised to use", async () => {
		server.use(
			http.get("*/user/tokens/verify", () =>
				HttpResponse.json({
					success: true,
					result: { id: "token-1", status: "active" },
				})
			),
			http.get("*/user", () =>
				HttpResponse.json({
					success: true,
					result: { email: "user@example.com" },
				})
			)
		);

		const mockAgent = new MockAgent();
		mockAgent.disableNetConnect();
		const api = mockAgent.get("https://api.test");
		api
			.intercept({
				path: "/client/v4/accounts?page=1",
				method: "GET",
			})
			.reply(200, {
				success: true,
				result: [
					{ id: "account-1", name: "Account One", settings: {} },
					{ id: "account-2", name: "Account Two", settings: {} },
					{ id: "account-3", name: "Account Three", settings: {} },
				],
				result_info: { page: 1, total_pages: 1 },
			});
		api
			.intercept({
				path: "/client/v4/memberships?page=1",
				method: "GET",
			})
			.reply(200, {
				success: true,
				result: [
					{ account: { id: "account-1", name: "Account One" } },
					{ account: { id: "account-3", name: "Account Three" } },
				],
				result_info: { page: 1, total_pages: 1 },
			});
		const previousDispatcher = getGlobalDispatcher();
		setGlobalDispatcher(mockAgent);

		try {
			await runCf(["auth", "whoami"], {
				CLOUDFLARE_API_TOKEN: "test-token",
				CLOUDFLARE_API_BASE_URL: TEST_BASE_URL,
			});
		} finally {
			setGlobalDispatcher(previousDispatcher);
			await mockAgent.close();
		}

		expect(JSON.parse(std.out)).toMatchObject({
			authenticated: true,
			tokenValid: true,
			email: "user@example.com",
			accounts: [
				{ id: "account-1", name: "Account One" },
				{ id: "account-3", name: "Account Three" },
			],
		});
	});

	it("reports tokenValid true for a valid scoped token that cannot read /user or accounts", async () => {
		// Scoped API tokens (e.g. DNS Edit on a single zone) get 403 from
		// /user and the account lookup, but /user/tokens/verify still
		// confirms the token is valid and active. See issue #21.
		server.use(
			http.get("*/user/tokens/verify", () =>
				HttpResponse.json({
					success: true,
					result: { id: "token-1", status: "active" },
				})
			),
			http.get("*/user", () =>
				HttpResponse.json(
					{
						success: false,
						errors: [
							{
								code: 9109,
								message: "Unauthorized to access requested resource",
							},
						],
					},
					{ status: 403 }
				)
			)
		);

		// The account lookup goes through undici directly, so mock it at the
		// dispatcher level: any request rejects (403-equivalent for a scoped
		// token with no account read permission).
		const mockAgent = new MockAgent();
		mockAgent.disableNetConnect();
		mockAgent
			.get("https://api.cloudflare.com")
			.intercept({ path: /.*/, method: "GET" })
			.reply(403, {
				success: false,
				errors: [
					{ code: 9109, message: "Unauthorized to access requested resource" },
				],
			});
		const previousDispatcher = getGlobalDispatcher();
		setGlobalDispatcher(mockAgent);

		try {
			await runCf(["auth", "whoami"], {
				CLOUDFLARE_API_TOKEN: "test-token",
				CLOUDFLARE_API_BASE_URL: TEST_BASE_URL,
			});
		} finally {
			setGlobalDispatcher(previousDispatcher);
			await mockAgent.close();
		}

		expect(JSON.parse(std.out)).toMatchObject({
			authenticated: true,
			tokenValid: true,
		});
		// No email/account read permission: these fields stay empty rather
		// than flipping tokenValid to false.
		const parsed = JSON.parse(std.out);
		expect(parsed.email).toBeUndefined();
		expect(parsed.accounts).toEqual([]);
	});
});
