import RelaynetError from './RelaynetError';
export interface PublicNodeAddress {
    readonly host: string;
    readonly port: number;
}
export declare enum BindingType {
    CRC = "awala-crc",
    GSC = "awala-gsc",
    PDC = "awala-pdc"
}
export declare class PublicAddressingError extends RelaynetError {
}
export declare class UnreachableResolverError extends RelaynetError {
}
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
export declare function resolvePublicAddress(hostName: string, bindingType: BindingType, resolverURL?: string): Promise<PublicNodeAddress | null>;
