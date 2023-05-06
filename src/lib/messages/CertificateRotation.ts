import { CertificationPath } from '../pki/CertificationPath';
import { generateFormatSignature } from './formatSignature';
import { InvalidMessageError } from './InvalidMessageError';

export const CERTIFICATE_ROTATION_FORMAT_SIGNATURE = generateFormatSignature(0x10, 0);

export class CertificateRotation {
  public static deserialize(serialization: ArrayBuffer): CertificateRotation {
    const formatSignature = Buffer.from(
      serialization.slice(0, CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength),
    );
    if (!formatSignature.equals(CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
      throw new InvalidMessageError('Format signature should be that of a CertificateRotation');
    }

    const certificationPathSerialized = serialization.slice(formatSignature.byteLength);
    let certificationPath: CertificationPath;
    try {
      certificationPath = CertificationPath.deserialize(certificationPathSerialized);
    } catch (err) {
      throw new InvalidMessageError(err as Error, 'CertificationPath is malformed');
    }

    return new CertificateRotation(certificationPath);
  }

  constructor(public readonly certificationPath: CertificationPath) {}

  public serialize(): ArrayBuffer {
    const pathSerialized = this.certificationPath.serialize();
    const serialization = new ArrayBuffer(
      CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength + pathSerialized.byteLength,
    );
    const serializationView = new Uint8Array(serialization);
    serializationView.set(CERTIFICATE_ROTATION_FORMAT_SIGNATURE, 0);
    serializationView.set(
      new Uint8Array(pathSerialized),
      CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength,
    );
    return serialization;
  }
}
