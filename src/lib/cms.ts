import * as pkijs from 'pkijs';
import * as oids from './oids';
import Certificate from './pki/Certificate';

export function sign(signerCertificate: Certificate): ArrayBuffer {
  const signerInfo = new pkijs.SignerInfo({
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: signerCertificate.pkijsCertificate.issuer,
      serialNumber: signerCertificate.pkijsCertificate.serialNumber
    }),
    version: 1
  });
  const cmsSigned = new pkijs.SignedData({
    signerInfos: [signerInfo],
    version: 1
  });
  const contentInfo = new pkijs.ContentInfo({
    content: cmsSigned.toSchema(true),
    contentType: oids.CMS_SIGNED_DATA
  });
  return contentInfo.toSchema().toBER(false);
}
