import { DNSoverHTTPS } from 'dohdec';

import RelaynetError from './RelaynetError';

const CLOUDFLARE_RESOLVER_URL = 'https://cloudflare-dns.com/dns-query';

export interface PublicNodeAddress {
  readonly host: string;
  readonly port: number;
}

export enum BindingType {
  PDC = 'rpdc',
  CRC = 'rcrc',
}

export class PublicAddressingError extends RelaynetError {}

/**
 * Return public node address for `hostName` if it has a valid SRV record.
 *
 * @param hostName The host name to look up
 * @param bindingType The SRV service to look up
 * @param resolverURL The URL for the DNS-over-HTTPS resolver
 * @throws If DNSSEC verification failed or the DNS resolver was unreachable
 *
 * `null` is returned when `hostName` is an IP address or a non-existing SRV record for the service
 * in `bindingType`.
 */
export async function resolvePublicAddress(
  hostName: string,
  bindingType: BindingType,
  resolverURL = CLOUDFLARE_RESOLVER_URL,
): Promise<PublicNodeAddress | null> {
  const name = `_${bindingType}._tcp.${hostName}`;
  const doh = new DNSoverHTTPS({ url: resolverURL });
  const result = await doh.getDNS({ dnssec: true, name, rrtype: 'SRV', decode: true });
  if (!result.flag_ad) {
    throw new PublicAddressingError(`DNSSEC verification for SRV ${name} failed`);
  }
  if (result.rcode !== 'NOERROR') {
    // hostName is an IP address or a domain name without the expected SRV record
    return null;
  }
  const srvAnswers = result.answers.filter((a) => a.type === 'SRV');
  // TODO: Pick the best answer based on its weight and priority fields
  const answer = srvAnswers[0];
  if (!answer || !answer.data || !answer.data.target || !answer.data.port) {
    // This is a malformed response, but let's handle it gracefully
    return null;
  }
  return { host: removeTrailingDot(answer.data.target), port: answer.data.port };
}

function removeTrailingDot(host: string): string {
  return host.replace(/\.$/, '');
}
