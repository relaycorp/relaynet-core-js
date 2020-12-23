declare module 'dohdec' {
  interface DOHOptions {
    readonly url: string;
  }

  interface LookupOptions {
    readonly decode: boolean;
    readonly dnssec: boolean;
    readonly name: string;
    readonly rrtype: string;
  }
  interface LookupResult {
    readonly flag_ad: boolean;
    readonly answers: readonly LookupResultAnswer[];
    readonly rcode: string;
  }
  interface LookupResultAnswer {
    readonly data: LookupAnswerData;
    readonly name: string;
    readonly type: string;
  }
  interface LookupAnswerData {
    readonly priority: number;
    readonly weight: number;
    readonly port: number;
    readonly target: string;
  }

  export class DNSoverHTTPS {
    constructor(opts: DOHOptions);

    public getDNS(opts: LookupOptions): Promise<LookupResult>;
  }
}
