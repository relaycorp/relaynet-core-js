import { OctetString, Sequence } from 'asn1js';

import { makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto_wrappers/_utils';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { CertificationPath } from './CertificationPath';

/**
 * Store of certificates.
 */
export abstract class CertificateStore {
  /**
   * Store `subjectCertificate` as long as it's still valid.
   *
   * @param subjectCertificate
   * @param chain
   * @param issuerPrivateAddress
   *
   * Whilst we could take the {issuerPrivateAddress} from the {subjectCertificate}, we must not
   * rely on it because we don't have enough information/context here to be certain that the
   * value is legitimate. Additionally, the value has to be present in an X.509 extension, which
   * could be absent if produced by a non-compliant implementation.
   */
  public async save(
    subjectCertificate: Certificate,
    chain: readonly Certificate[],
    issuerPrivateAddress: string,
  ): Promise<void> {
    if (new Date() < subjectCertificate.expiryDate) {
      const sequence = makeImplicitlyTaggedSequence(
        new OctetString({ valueHex: subjectCertificate.serialize() }),
        new Sequence({ value: chain.map((c) => new OctetString({ valueHex: c.serialize() })) }),
      );
      await this.saveData(
        sequence.toBER(),
        await subjectCertificate.calculateSubjectPrivateAddress(),
        subjectCertificate.expiryDate,
        issuerPrivateAddress,
      );
    }
  }

  public async retrieveLatest(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<CertificationPath | null> {
    const serialization = await this.retrieveLatestSerialization(
      subjectPrivateAddress,
      issuerPrivateAddress,
    );
    if (!serialization) {
      return null;
    }
    const path = deserializeCertificatePath(serialization);
    return new Date() < path.leafCertificate.expiryDate ? path : null;
  }

  public async retrieveAll(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<readonly CertificationPath[]> {
    const allSerializations = await this.retrieveAllSerializations(
      subjectPrivateAddress,
      issuerPrivateAddress,
    );
    return allSerializations
      .map(deserializeCertificatePath)
      .filter((p) => new Date() < p.leafCertificate.expiryDate);
  }

  public abstract deleteExpired(): Promise<void>;

  protected abstract saveData(
    serialization: ArrayBuffer,
    subjectPrivateAddress: string,
    subjectCertificateExpiryDate: Date,
    issuerPrivateAddress: string,
  ): Promise<void>;

  protected abstract retrieveLatestSerialization(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<ArrayBuffer | null>;

  protected abstract retrieveAllSerializations(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<readonly ArrayBuffer[]>;
}

function deserializeCertificatePath(pathSerialized: ArrayBuffer): CertificationPath {
  const deserialization = derDeserialize(pathSerialized);
  const leafCertificate = Certificate.deserialize(
    deserialization.valueBlock.value[0].valueBlock.valueHex,
  );
  const chain = deserialization.valueBlock.value[1].valueBlock.value.map((b: OctetString) =>
    Certificate.deserialize(b.valueBlock.valueHex),
  );
  return { leafCertificate, chain };
}
