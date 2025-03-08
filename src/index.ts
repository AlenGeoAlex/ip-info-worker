/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const aclResponse = await ensureAcl(env, request);
		if(typeof aclResponse === 'string'){
			return new Response(JSON.stringify({
				error: "unauthorized",
				message: aclResponse,
			}), {
				status: 401,
				headers: {
					'content-type': 'application/json',
				}
			});
		}else{
			if(!aclResponse)
				return new Response(null, {
					status: 401
				});
		}

		const url = new URL(request.url);
		if(url.searchParams.has('mode') && (url.searchParams.get('mode') || '').trim() === 'basic'){
			return getBasic(request.cf);
		}

		url.searchParams.delete('mode');
		url.protocol = 'http';
		url.host = "ip-api.com";

		return await fetch(url.toString());
	},
} satisfies ExportedHandler<Env>;

function getBasic(prop: IncomingRequestCfProperties<unknown> | undefined) : Response {
	return new Response(JSON.stringify(prop));
}

async function ensureAcl(env: Env, req: Request): Promise<boolean | string> {
	const originAddress = req.headers.get("CF-Connecting-IP") || '';
	if(!originAddress)
		return false;

	if(!env.acl)
		return false;

	if(!req.headers.has('X-API-KEY'))
		return "Api key is required. Please provide an API key";

	const apiKey = (req.headers.get('X-API-KEY') || '').trim();
	if (!apiKey || apiKey.trim().length === 0)
		return "Api key is required. Please provide an API key";

	if(!req.headers.has("CF-Connecting-IP"))
		return false;

	const preparedStatement = env.acl.prepare("SELECT * FROM 'access-control' WHERE api_key = ?")
		.bind(apiKey);

	const acl = await preparedStatement.first();
	if(!acl)
		return false;

	let aclElement = acl["allowed_addresses"];
	if(!aclElement || typeof aclElement !== "string")
		return false;

	let aclAddresses : string[] | never;
	try {
		aclAddresses = JSON.parse(aclElement) as string[];
	}catch(err) {
		return "An error occurred while parsing acl";
	}

	if(aclAddresses.length === 0)
		return true;

	if(!aclAddresses.includes(originAddress))
		return "The origin address is not allowed to use this api. Please refrain from using this";

	return true;
}
