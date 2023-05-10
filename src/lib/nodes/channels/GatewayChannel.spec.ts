import bufferToArray from 'buffer-to-arraybuffer';
import { addDays, addSeconds, setMilliseconds } from 'date-fns';

import {
  arrayToAsyncIterable,
  asyncIterableToArray,
  CRYPTO_OIDS,
  reSerializeCertificate,
} from '../../_test_utils';
import { EnvelopedData, SessionEnvelopedData } from '../../crypto/cms/envelopedData';
import { SignatureOptions } from '../../crypto/cms/SignatureOptions';
import { generateRSAKeyPair } from '../../crypto/keys/generation';
import { Certificate } from '../../crypto/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { Cargo } from '../../messages/Cargo';
import { Parcel } from '../../messages/Parcel';
import { CargoMessageSet } from '../../messages/payloads/CargoMessageSet';
import { ServiceMessage } from '../../messages/payloads/ServiceMessage';
import { issueGatewayCertificate } from '../../pki/issuance';
import { RAMF_MAX_TTL } from '../../ramf/serialization';
import { SessionKey } from '../../SessionKey';
import { SessionKeyPair } from '../../SessionKeyPair';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { GatewayChannel } from './GatewayChannel';
import { getIdFromIdentityKey } from '../../crypto/keys/digest';
import { StubGateway } from './_test_utils';

const MESSAGE = Buffer.from('This is a message to be included in a cargo');

const TOMORROW = setMilliseconds(addDays(new Date(), 1), 0);

let peerId: string;
let peerPublicKey: CryptoKey;
let node: StubGateway;
let deliveryAuth: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  const peerKeyPair = await generateRSAKeyPair();
  peerId = await getIdFromIdentityKey(peerKeyPair.publicKey);
  peerPublicKey = peerKeyPair.publicKey;
  const peerCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: peerKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  const nodeKeyPair = await generateRSAKeyPair();
  node = new StubGateway(
    await getIdFromIdentityKey(nodeKeyPair.publicKey),
    nodeKeyPair,
    KEY_STORES,
    {},
  );
  deliveryAuth = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: peerCertificate,
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
});

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('generateCargoes', () => {
  let peerSessionKeyPair: SessionKeyPair;
  beforeAll(async () => {
    peerSessionKeyPair = await SessionKeyPair.generate();
  });

  beforeEach(async () => {
    await KEY_STORES.publicKeyStore.saveSessionKey(
      peerSessionKeyPair.sessionKey,
      peerId,
      new Date(),
    );
  });

  test('Recipient address should correspond to that of peer', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    expect(cargo.recipient.id).toEqual(peerId);
  });

  test('Payload should be encrypted with session key', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
    expect(cargoPayload).toBeInstanceOf(SessionEnvelopedData);
    expect(cargoPayload.getRecipientKeyId()).toEqual(peerSessionKeyPair.sessionKey.keyId);
  });

  test('New ephemeral session key should be stored when using channel session', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
    const originatorKey = await (cargoPayload as SessionEnvelopedData).getOriginatorKey();
    await expect(
      KEY_STORES.privateKeyStore.retrieveSessionKey(
        originatorKey.keyId,
        await deliveryAuth.calculateSubjectId(),
        peerId,
      ),
    ).toResolve();
  });

  test('Encryption options should be honored if present', async () => {
    const aesKeySize = 192;
    const channel = new StubGatewayChannel({ encryption: { aesKeySize } });

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ]),
      ),
    );

    expect(await getCargoPayloadEncryptionAlgorithmId(cargoesSerialized[0])).toEqual(
      CRYPTO_OIDS.AES_CBC_192,
    );
  });

  test('Cargo should be signed with the specified key', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    expect(deliveryAuth.isEqual(cargo.senderCertificate)).toBeTrue();
  });

  test('Signature options should be honored if present', async () => {
    const signatureOptions: SignatureOptions = { hashingAlgorithmName: 'SHA-384' };
    const channel = new StubGatewayChannel({ signature: signatureOptions });
    const cargoSerializeSpy = jest.spyOn(Cargo.prototype, 'serialize');

    await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ]),
      ),
    );

    expect(cargoSerializeSpy).toBeCalledTimes(1);
    expect(cargoSerializeSpy).toBeCalledWith(expect.anything(), signatureOptions);
  });

  test('Cargo creation date should be 3 hours in the past', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            message: MESSAGE,
            expiryDate: TOMORROW,
          },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    const expectedCreationDate = new Date();
    expectedCreationDate.setHours(expectedCreationDate.getHours() - 3);
    expect(cargo.creationDate.getTime()).toBeWithin(
      expectedCreationDate.getTime() - 5_000,
      expectedCreationDate.getTime() + 5_000,
    );
  });

  test('Cargo TTL should be that of the message with the latest TTL', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          { message: MESSAGE, expiryDate: TOMORROW },
          { message: MESSAGE, expiryDate: new Date() },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    expect(cargo.expiryDate).toEqual(TOMORROW);
  });

  test('Cargo TTL should not exceed maximum RAMF TTL', async () => {
    const channel = new StubGatewayChannel();

    const now = new Date();
    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          {
            message: MESSAGE,
            expiryDate: addSeconds(now, RAMF_MAX_TTL + 10),
          },
        ]),
      ),
    );

    const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
    expect(cargo.ttl).toEqual(RAMF_MAX_TTL);
  });

  test('Zero cargoes should be output if there are zero messages', async () => {
    const channel = new StubGatewayChannel();

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(arrayToAsyncIterable([])),
    );

    expect(cargoesSerialized).toHaveLength(0);
  });

  test('Messages should be encapsulated into as few cargoes as possible', async () => {
    const channel = new StubGatewayChannel();
    const dummyParcel = await generateDummyParcel(
      peerId,
      peerSessionKeyPair.sessionKey,
      deliveryAuth,
    );
    const dummyParcelSerialized = await dummyParcel.serialize(node.identityKeyPair.privateKey);

    const cargoesSerialized = await asyncIterableToArray(
      channel.generateCargoes(
        arrayToAsyncIterable([
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
        ]),
      ),
    );

    expect(cargoesSerialized).toHaveLength(1);
    const messageSet = await extractMessageSetFromCargo(cargoesSerialized[0]);
    expect(messageSet.messages.length).toEqual(3);
    expect(Array.from(messageSet.messages)).toEqual([
      dummyParcelSerialized,
      dummyParcelSerialized,
      dummyParcelSerialized,
    ]);
  });

  async function extractMessageSetFromCargo(cargoSerialized: Buffer): Promise<CargoMessageSet> {
    const cargo = await Cargo.deserialize(bufferToArray(cargoSerialized));
    const { payload } = await cargo.unwrapPayload(peerSessionKeyPair.privateKey);
    return payload;
  }

  async function getCargoPayloadEncryptionAlgorithmId(cargoSerialized: Buffer): Promise<string> {
    const cargo = await Cargo.deserialize(bufferToArray(cargoSerialized));
    const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
    const encryptedContentInfo = cargoPayload.pkijsEnvelopedData.encryptedContentInfo;
    return encryptedContentInfo.contentEncryptionAlgorithm.algorithmId;
  }
});

async function generateDummyParcel(
  recipientId: string,
  recipientSessionKey: SessionKey,
  finalSenderCertificate: Certificate,
): Promise<Parcel> {
  const serviceMessage = new ServiceMessage('a', Buffer.from('the payload'));
  const serviceMessageSerialized = await serviceMessage.serialize();
  const { envelopedData } = await SessionEnvelopedData.encrypt(
    serviceMessageSerialized,
    recipientSessionKey,
  );
  const payloadSerialized = Buffer.from(envelopedData.serialize());
  return new Parcel({ id: recipientId }, finalSenderCertificate, payloadSerialized);
}

class StubGatewayChannel extends GatewayChannel {
  constructor(cryptoOptions: Partial<NodeCryptoOptions> = {}) {
    super(node, deliveryAuth, peerId, peerPublicKey, KEY_STORES, cryptoOptions);
  }
}
