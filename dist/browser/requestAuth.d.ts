import { AuthResponseBundle, RequestedClaim } from "../types.js";
import { RequestAuthOptions } from "./wallet.js";
interface PQIDExtensionApi {
    requestAuth: (purpose: string, claims: Array<{
        type: string;
        value: string;
        purpose?: string;
    }>, options?: {
        challenge?: string;
        audience?: string;
        appId?: string;
        appName?: string;
        appDescription?: string;
        iconUrl?: string;
        appHandle?: string;
    }) => Promise<{
        status: "approved";
        bundle?: AuthResponseBundle;
        error?: string;
        appHandle?: string;
    } | {
        status: "rejected";
        error?: string;
    }>;
}
declare global {
    interface Window {
        pqid?: PQIDExtensionApi;
    }
}
/**
 * requestAuth
 *
 * Called by a relying party's frontend code.
 * Automatically detects environment and uses appropriate auth method:
 * - Browser with extension: Use PQID wallet extension
 * - Browser without extension: Use built-in development wallet
 * - Node.js/Test environment: Use server-side development wallet
 *
 * Returns a complete AuthResponseBundle with PQ-signed assertions and credentials.
 */
export declare function requestAuth(opts: RequestAuthOptions & {
    requested_claims: RequestedClaim[];
}): Promise<AuthResponseBundle>;
export type { RequestAuthOptions } from "./wallet.js";
//# sourceMappingURL=requestAuth.d.ts.map