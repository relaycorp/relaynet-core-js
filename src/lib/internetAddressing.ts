// tslint:disable:max-classes-per-file

import { DNSoverHTTPS, LookupResult } from 'dohdec';

import { RelaynetError } from './RelaynetError';

const CLOUDFLARE_RESOLVER_URL = 'https://cloudflare-dns.com/dns-query';

export interface PublicNodeAddress {
  readonly host: string;
  readonly port: number;
}

export enum BindingType {
  CRC = 'awala-crc',
  GSC = 'awala-gsc',
  PDC = 'awala-pdc',
}

export class InternetAddressingError extends RelaynetError {}

export class UnreachableResolverError extends RelaynetError {}

/**
 * Return public node address for `hostName` if it has a valid SRV record.
 *
 * @param hostName The host name to look up
 * @param bindingType The SRV service to look up
 * @param resolverURL The URL for the DNS-over-HTTPS resolver
 * @throws {InternetAddressingError} If DNSSEC verification failed
 * @throws {UnreachableResolverError} If the DNS resolver was unreachable
 *
 * `null` is returned when `hostName` is an IP address or a non-existing SRV record for the service
 * in `bindingType`.
 *
 * DNS resolution is done with DNS-over-HTTPS.
 */
export async function resolveInternetAddress(
  hostName: string,
  bindingType: BindingType,
  resolverURL = CLOUDFLARE_RESOLVER_URL,
): Promise<PublicNodeAddress | null> {
  const name = `_${bindingType}._tcp.${hostName}`;
  const doh = new DNSoverHTTPS({ url: resolverURL });
  let result: LookupResult;
  try {
    result = await doh.getDNS({ dnssec: true, name, rrtype: 'SRV', decode: true });
  } catch (error: any) {
    throw error.errno === 'ENOTFOUND'
      ? new UnreachableResolverError(error, 'Failed to reach DoH resolver')
      : error;
  }
  if (result.rcode === 'NXDOMAIN') {
    // hostName is an IP address or a domain name without the expected SRV record
    return null;
  }
  if (result.rcode !== 'NOERROR') {
    throw new InternetAddressingError(`SRV lookup for ${name} failed with status ${result.rcode}`);
  }
  if (!result.flag_ad) {
    throw new InternetAddressingError(`DNSSEC verification for SRV ${name} failed`);
  }
  const srvAnswers = result.answers.filter((a) => a.type === 'SRV');
  // TODO: Pick the best answer based on its weight and priority fields
  const answer = srvAnswers[0];
  if (!answer || !answer.data || !answer.data.target || !answer.data.port) {
    throw new InternetAddressingError('DNS answer is malformed');
  }
  return { host: removeTrailingDot(answer.data.target), port: answer.data.port };
}

function removeTrailingDot(host: string): string {
  return host.replace(/\.$/, '');
}
