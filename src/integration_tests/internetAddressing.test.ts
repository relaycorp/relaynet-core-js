import { BindingType, resolveInternetAddress } from '..';

describe('resolveInternetAddress', () => {
  const EXISTING_INTERNET_ADDRESS = 'frankfurt.relaycorp.cloud';
  const NON_EXISTING_ADDRESS = 'unlikely-to-ever-exist-f5e6yht34.relaycorp.cloud';

  test('Existing address should be resolved', async () => {
    const address = await resolveInternetAddress(EXISTING_INTERNET_ADDRESS, BindingType.PDC);

    expect(address?.host).toBeString();
    expect(address?.port).toBeNumber();
  });

  test('Google DNS should be supported', async () => {
    // This is important to check because CloudFlare and Google DNS resolvers are slightly
    // different. For example, Google's adds a trailing dot to the target host.

    const cfAddress = await resolveInternetAddress(EXISTING_INTERNET_ADDRESS, BindingType.PDC);
    const gAddress = await resolveInternetAddress(
      EXISTING_INTERNET_ADDRESS,
      BindingType.PDC,
      'https://dns.google/dns-query',
    );

    expect(cfAddress).toEqual(gAddress);
  });

  test('Invalid DNSSEC configuration should be refused', async () => {
    await expect(resolveInternetAddress('dnssec-failed.org', BindingType.PDC)).toReject();
  });

  test('Non-existing addresses should not be resolved', async () => {
    await expect(resolveInternetAddress(NON_EXISTING_ADDRESS, BindingType.PDC)).resolves.toBeNull();
  });

  test('Non-existing address should resolve if port is contained', async () => {
    const port = 1234;
    await expect(
      resolveInternetAddress(`${NON_EXISTING_ADDRESS}:${port}`, BindingType.PDC),
    ).resolves.toEqual({ host: NON_EXISTING_ADDRESS, port });
  });
});
