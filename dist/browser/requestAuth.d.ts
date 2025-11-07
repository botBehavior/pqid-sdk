import { AuthResponseBundle, RequestedClaim } from "../types.js";
import { RequestAuthOptions } from "./wallet.js";
/**
 * requestAuth
 *
 * Called by a relying party's frontend code.
 * Eventually this will talk to the PQID wallet extension via window.pqid.requestAuth(...)
 * and ask the user to approve sharing certain claims.
 *
 * For v0.1.2 this provisions a development Ed25519 wallet key pair, issues
 * credentials from the dev issuer, and returns a signed AuthResponseBundle.
 */
export declare function requestAuth(opts: RequestAuthOptions & {
    requested_claims: RequestedClaim[];
}): Promise<AuthResponseBundle>;
export type { RequestAuthOptions } from "./wallet.js";
//# sourceMappingURL=requestAuth.d.ts.map