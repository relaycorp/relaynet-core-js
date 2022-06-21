import Certificate from '../../crypto_wrappers/x509/Certificate';
import { GatewayChannel } from './GatewayChannel';
/**
 * Channel whose node is a private gateway.
 */
export declare abstract class PrivateGatewayChannel extends GatewayChannel {
    getOrCreateCDAIssuer(): Promise<Certificate>;
    /**
     * Get all CDA issuers in the channel.
     */
    getCDAIssuers(): Promise<readonly Certificate[]>;
}
