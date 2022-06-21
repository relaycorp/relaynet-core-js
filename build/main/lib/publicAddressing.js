"use strict";
// tslint:disable:max-classes-per-file
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolvePublicAddress = exports.UnreachableResolverError = exports.PublicAddressingError = exports.BindingType = void 0;
const dohdec_1 = require("dohdec");
const RelaynetError_1 = __importDefault(require("./RelaynetError"));
const CLOUDFLARE_RESOLVER_URL = 'https://cloudflare-dns.com/dns-query';
var BindingType;
(function (BindingType) {
    BindingType["CRC"] = "awala-crc";
    BindingType["GSC"] = "awala-gsc";
    BindingType["PDC"] = "awala-pdc";
})(BindingType = exports.BindingType || (exports.BindingType = {}));
class PublicAddressingError extends RelaynetError_1.default {
}
exports.PublicAddressingError = PublicAddressingError;
class UnreachableResolverError extends RelaynetError_1.default {
}
exports.UnreachableResolverError = UnreachableResolverError;
/**
 * Return public node address for `hostName` if it has a valid SRV record.
 *
 * @param hostName The host name to look up
 * @param bindingType The SRV service to look up
 * @param resolverURL The URL for the DNS-over-HTTPS resolver
 * @throws PublicAddressingError If DNSSEC verification failed
 * @throws UnreachableResolverError If the DNS resolver was unreachable
 *
 * `null` is returned when `hostName` is an IP address or a non-existing SRV record for the service
 * in `bindingType`.
 *
 * If `hostName` contains the port number (e.g., `example.com:443`), no DNS lookup will be done
 * and the resulting address will simply be the result of parsing the input.
 *
 * DNS resolution is done with DNS-over-HTTPS.
 */
async function resolvePublicAddress(hostName, bindingType, resolverURL = CLOUDFLARE_RESOLVER_URL) {
    const urlParts = new URL(`scheme://${hostName}`);
    if (urlParts.port !== '') {
        const port = parseInt(urlParts.port, 10);
        return { host: urlParts.hostname, port };
    }
    const name = `_${bindingType}._tcp.${hostName}`;
    const doh = new dohdec_1.DNSoverHTTPS({ url: resolverURL });
    let result;
    try {
        result = await doh.getDNS({ dnssec: true, name, rrtype: 'SRV', decode: true });
    }
    catch (error) {
        throw error.errno === 'ENOTFOUND'
            ? new UnreachableResolverError(error, 'Failed to reach DoH resolver')
            : error;
    }
    if (result.rcode === 'NXDOMAIN') {
        // hostName is an IP address or a domain name without the expected SRV record
        return null;
    }
    if (result.rcode !== 'NOERROR') {
        throw new PublicAddressingError(`SRV lookup for ${name} failed with status ${result.rcode}`);
    }
    if (!result.flag_ad) {
        throw new PublicAddressingError(`DNSSEC verification for SRV ${name} failed`);
    }
    const srvAnswers = result.answers.filter((a) => a.type === 'SRV');
    // TODO: Pick the best answer based on its weight and priority fields
    const answer = srvAnswers[0];
    if (!answer || !answer.data || !answer.data.target || !answer.data.port) {
        throw new PublicAddressingError('DNS answer is malformed');
    }
    return { host: removeTrailingDot(answer.data.target), port: answer.data.port };
}
exports.resolvePublicAddress = resolvePublicAddress;
function removeTrailingDot(host) {
    return host.replace(/\.$/, '');
}
//# sourceMappingURL=publicAddressing.js.map