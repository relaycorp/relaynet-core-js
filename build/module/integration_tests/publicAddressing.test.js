import { BindingType, resolvePublicAddress } from '..';
describe('resolvePublicAddress', () => {
    const EXISTING_PUBLIC_ADDRESS = 'frankfurt.relaycorp.cloud';
    const NON_EXISTING_ADDRESS = 'unlikely-to-ever-exist.relaycorp.cloud';
    test('Existing address should be resolved', async () => {
        const address = await resolvePublicAddress(EXISTING_PUBLIC_ADDRESS, BindingType.PDC);
        expect(address?.host).toBeString();
        expect(address?.port).toBeNumber();
    });
    test('Google DNS should be supported', async () => {
        // This is important to check because CloudFlare and Google DNS resolvers are slightly
        // different. For example, Google's adds a trailing dot to the target host.
        const cfAddress = await resolvePublicAddress(EXISTING_PUBLIC_ADDRESS, BindingType.PDC);
        const gAddress = await resolvePublicAddress(EXISTING_PUBLIC_ADDRESS, BindingType.PDC, 'https://dns.google/dns-query');
        expect(cfAddress).toEqual(gAddress);
    });
    test('Invalid DNSSEC configuration should be refused', async () => {
        await expect(resolvePublicAddress('dnssec-failed.org', BindingType.PDC)).toReject();
    });
    test('Non-existing addresses should not be resolved', async () => {
        await expect(resolvePublicAddress(NON_EXISTING_ADDRESS, BindingType.PDC)).resolves.toBeNull();
    });
    test('Non-existing address should resolve if port is contained', async () => {
        const port = 1234;
        await expect(resolvePublicAddress(`${NON_EXISTING_ADDRESS}:${port}`, BindingType.PDC)).resolves.toEqual({ host: NON_EXISTING_ADDRESS, port });
    });
});
//# sourceMappingURL=publicAddressing.test.js.map