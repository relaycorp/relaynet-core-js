import { addDays, subMinutes } from 'date-fns';
import { getPrivateAddressFromIdentityKey, getRSAPublicKeyFromPrivate, } from '../../crypto_wrappers/keys';
import { CertificationPath } from '../../pki/CertificationPath';
import { issueGatewayCertificate } from '../../pki/issuance';
import { GatewayChannel } from './GatewayChannel';
/**
 * Channel whose node is a private gateway.
 */
export class PrivateGatewayChannel extends GatewayChannel {
    async getOrCreateCDAIssuer() {
        const now = new Date();
        const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
        const privateAddress = await getPrivateAddressFromIdentityKey(publicKey);
        const existingIssuerPath = await this.keyStores.certificateStore.retrieveLatest(privateAddress, privateAddress);
        if (existingIssuerPath) {
            const minExpiryDate = addDays(now, 90);
            if (minExpiryDate <= existingIssuerPath.leafCertificate.expiryDate) {
                return existingIssuerPath.leafCertificate;
            }
        }
        const issuer = await issueGatewayCertificate({
            issuerPrivateKey: this.nodePrivateKey,
            subjectPublicKey: publicKey,
            validityEndDate: addDays(now, 180),
            validityStartDate: subMinutes(now, 90),
        });
        const path = new CertificationPath(issuer, []);
        await this.keyStores.certificateStore.save(path, privateAddress);
        return issuer;
    }
    /**
     * Get all CDA issuers in the channel.
     */
    async getCDAIssuers() {
        const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
        const privateAddress = await getPrivateAddressFromIdentityKey(publicKey);
        const issuerPaths = await this.keyStores.certificateStore.retrieveAll(privateAddress, privateAddress);
        return issuerPaths.map((p) => p.leafCertificate);
    }
}
//# sourceMappingURL=PrivateGatewayChannel.js.map