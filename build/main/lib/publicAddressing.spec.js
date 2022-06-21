"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const _test_utils_1 = require("./_test_utils");
const HOST = 'test.relaycorp.cloud';
const HOST_SRV_NAME = `_awala-pdc._tcp.${HOST}`;
const TARGET_HOST = 'test-pdc.relaycorp.cloud';
const TARGET_PORT = 443;
const SUCCESSFUL_RESPONSE = {
    answers: [
        {
            data: {
                port: TARGET_PORT,
                priority: 0,
                target: TARGET_HOST,
                weight: 1,
            },
            name: HOST,
            type: 'SRV',
        },
    ],
    flag_ad: true,
    rcode: 'NOERROR',
};
const mockGetDNS = (0, _test_utils_1.mockSpy)(jest.fn(), () => SUCCESSFUL_RESPONSE);
const mockDOH = (0, _test_utils_1.mockSpy)(jest.fn(), () => ({ getDNS: mockGetDNS }));
jest.mock('dohdec', () => ({
    DNSoverHTTPS: mockDOH,
}));
const publicAddressing_1 = require("./publicAddressing");
describe('resolvePublicAddress', () => {
    const MALFORMED_ANSWER_ERROR = new publicAddressing_1.PublicAddressingError('DNS answer is malformed');
    test('DNS resolution should be skipped if host name contains port', async () => {
        const address = await (0, publicAddressing_1.resolvePublicAddress)(`${HOST}:${TARGET_PORT}`, publicAddressing_1.BindingType.PDC);
        expect(address).toHaveProperty('host', HOST);
        expect(address).toHaveProperty('port', TARGET_PORT);
        expect(mockGetDNS).not.toBeCalled();
    });
    test('Specified domain name should be requested', async () => {
        await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(mockGetDNS).toBeCalledWith(expect.objectContaining({ name: `_${publicAddressing_1.BindingType.PDC}._tcp.${HOST}` }));
    });
    test('DNSSEC verification should be requested', async () => {
        await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(mockGetDNS).toBeCalledWith(expect.objectContaining({ dnssec: true }));
    });
    test('SRV record should be requested', async () => {
        await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(mockGetDNS).toBeCalledWith(expect.objectContaining({ name: HOST_SRV_NAME, rrtype: 'SRV' }));
    });
    test('CloudFlare resolver should be used by default', async () => {
        await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(mockDOH).toBeCalledWith(expect.objectContaining({ url: 'https://cloudflare-dns.com/dns-query' }));
    });
    test('DNS resolver should be customizable', async () => {
        const resolverURL = 'https://dns.example.com/dns-query';
        await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC, resolverURL);
        expect(mockDOH).toBeCalledWith(expect.objectContaining({ url: resolverURL }));
    });
    test('Null should be returned if domain does not exist', async () => {
        mockGetDNS.mockReturnValue({ ...SUCCESSFUL_RESPONSE, rcode: 'NXDOMAIN' });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).resolves.toBeNull();
    });
    test('An error should be thrown if DNS lookup status is not NOERROR', async () => {
        const status = 'SERVFAIL';
        mockGetDNS.mockReturnValue({ ...SUCCESSFUL_RESPONSE, rcode: status });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toEqual(new publicAddressing_1.PublicAddressingError(`SRV lookup for ${HOST_SRV_NAME} failed with status ${status}`));
    });
    test('An error should be thrown if the Answer is empty', async () => {
        mockGetDNS.mockReturnValue({ ...SUCCESSFUL_RESPONSE, answers: [] });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toEqual(MALFORMED_ANSWER_ERROR);
    });
    test('An error should be thrown if the Answer data is absent', async () => {
        mockGetDNS.mockReturnValue({
            ...SUCCESSFUL_RESPONSE,
            answers: [
                {
                    ...SUCCESSFUL_RESPONSE.answers[0],
                    data: undefined,
                },
            ],
        });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toEqual(MALFORMED_ANSWER_ERROR);
    });
    test('An error should be thrown if the Answer host is absent', async () => {
        mockGetDNS.mockReturnValue({
            ...SUCCESSFUL_RESPONSE,
            answers: [
                {
                    ...SUCCESSFUL_RESPONSE.answers[0],
                    data: { ...SUCCESSFUL_RESPONSE.answers[0].data, target: undefined },
                },
            ],
        });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toEqual(MALFORMED_ANSWER_ERROR);
    });
    test('An error should be thrown if the Answer port is absent', async () => {
        mockGetDNS.mockReturnValue({
            ...SUCCESSFUL_RESPONSE,
            answers: [
                {
                    ...SUCCESSFUL_RESPONSE.answers[0],
                    data: { ...SUCCESSFUL_RESPONSE.answers[0].data, port: undefined },
                },
            ],
        });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toEqual(MALFORMED_ANSWER_ERROR);
    });
    test('UnreachableResolverError should be thrown if resolver is unreachable', async () => {
        const networkError = new Error('Disconnected from Internet');
        // tslint:disable-next-line:no-object-mutation
        networkError.errno = 'ENOTFOUND';
        mockGetDNS.mockRejectedValue(networkError);
        const error = await (0, _test_utils_1.getPromiseRejection)((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC));
        expect(error).toBeInstanceOf(publicAddressing_1.UnreachableResolverError);
        expect(error.message).toMatch(/^Failed to reach DoH resolver:/);
        expect(error.cause()).toEqual(networkError);
    });
    test('Unexpected DNS lookup errors with the resolver should be propagated', async () => {
        const dnsLookupError = new Error('This is unexpected');
        mockGetDNS.mockRejectedValue(dnsLookupError);
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toBe(dnsLookupError);
    });
    test('An error should be thrown if DNSSEC verification fails', async () => {
        mockGetDNS.mockResolvedValue({ ...SUCCESSFUL_RESPONSE, flag_ad: false });
        await expect((0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC)).rejects.toEqual(new publicAddressing_1.PublicAddressingError(`DNSSEC verification for SRV _${publicAddressing_1.BindingType.PDC}._tcp.${HOST} failed`));
    });
    test('Address should be returned if record exists and is valid', async () => {
        const address = await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(address).toHaveProperty('host', TARGET_HOST);
        expect(address).toHaveProperty('port', TARGET_PORT);
    });
    test('Non-SRV answers should be skipped', async () => {
        mockGetDNS.mockReturnValue({
            ...SUCCESSFUL_RESPONSE,
            answers: [{ type: 'RRSIG' }, ...SUCCESSFUL_RESPONSE.answers],
        });
        const address = await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(address).toHaveProperty('host', TARGET_HOST);
        expect(address).toHaveProperty('port', TARGET_PORT);
    });
    test('Trailing dot (if present) should be removed from resolved host name', async () => {
        mockGetDNS.mockReturnValue({
            ...SUCCESSFUL_RESPONSE,
            answers: [
                {
                    ...SUCCESSFUL_RESPONSE.answers[0],
                    data: { ...SUCCESSFUL_RESPONSE.answers[0].data, target: `${TARGET_HOST}.` },
                },
            ],
        });
        const address = await (0, publicAddressing_1.resolvePublicAddress)(HOST, publicAddressing_1.BindingType.PDC);
        expect(address).toHaveProperty('host', TARGET_HOST);
    });
});
//# sourceMappingURL=publicAddressing.spec.js.map