import { DateTime, ObjectIdentifier, OctetString } from 'asn1js';

import { dateToASN1DateTimeInUTC, serializeSequence } from '../../../asn1';
import { sign } from '../../../crypto_wrappers/rsaSigning';
import { CRA } from '../../../oids';

export class ClientRegistrationAuthorization {
  private static makeSignaturePlaintext(
    expiryDateASN1: DateTime,
    serverDataASN1: OctetString,
  ): ArrayBuffer {
    return serializeSequence(new ObjectIdentifier({ value: CRA }), expiryDateASN1, serverDataASN1);
  }

  constructor(public readonly expiryDate: Date, public readonly serverData: ArrayBuffer) {}

  public async serialize(serverPrivateKey: CryptoKey): Promise<ArrayBuffer> {
    const expiryDateASN1 = dateToASN1DateTimeInUTC(this.expiryDate);
    const serverDataASN1 = new OctetString({ valueHex: this.serverData });
    const signaturePlaintext = ClientRegistrationAuthorization.makeSignaturePlaintext(
      expiryDateASN1,
      serverDataASN1,
    );
    const signature = await sign(signaturePlaintext, serverPrivateKey);
    return serializeSequence(
      expiryDateASN1,
      serverDataASN1,
      new OctetString({ valueHex: signature }),
    );
  }
}
