/**
 * Interface to get the MODP Groups per RFC 3526.
 *
 * The (original) JSON data was generated with the following script:
 *
 * ```
 * const crypto = require("crypto");
 * const fs = require("fs");
 *
 * const supportedModpNames = ["modp14", "modp15", "modp16", "modp17", "modp18"];
 * const modpsData = supportedModpNames.map(modpName => {
 *  const modp = crypto.createDiffieHellmanGroup(modpName);
 *  return {
 *    name: modpName,
 *    generator: [...modp.getGenerator()],
 *    prime: [...modp.getPrime()]
 *  };
 * });
 *
 * fs.writeFileSync("modp-groups.json", JSON.stringify(modpsData));
 * ```
 *
 * I couldn't find a reliable way to get this information:
 *
 * - NodeJS only seems to expose these values *after* you initialize a DH group, which is an
 *   overkill and very expensive (it took 15 seconds to run it with `modp18` on my computer).
 * - The NPM package `modp-groups` could've worked potentially, but it exposes the values using
 *   BigInteger which require converting to buffers. The package also hasn't been updated in 7
 *   years and only has 2 weekly downloads.
 */
import RelaynetError from '../RelaynetError';
import modpGroupsData from './modp-groups.json';

export type MODPGroupName = 'modp14' | 'modp15' | 'modp16' | 'modp17' | 'modp18';

export interface MODPGroup {
  readonly generator: Buffer;
  readonly prime: Buffer;
}

const MODP_GROUP_BY_NAME: { readonly [key: string]: MODPGroup } = modpGroupsData.reduce(
  (obj, groupData) => ({
    ...obj,
    [groupData.name]: {
      generator: Buffer.from(groupData.generator),
      prime: Buffer.from(groupData.prime),
    },
  }),
  {},
);

export function getModpGroupData(groupName: MODPGroupName): MODPGroup {
  if (!(groupName in MODP_GROUP_BY_NAME)) {
    throw new MODPError(`Unsupported MODP group (${groupName})`);
  }
  return MODP_GROUP_BY_NAME[groupName];
}

export class MODPError extends RelaynetError {}
