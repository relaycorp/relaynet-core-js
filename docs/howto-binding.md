---
title: Implementing a binding
nav_order: 2
---
# Implementing a binding

If you're implementing a binding, the only runtime dependency you may have on this library may be the [RelaynetError](./api/classes/relayneterror.html) class, which you may want to extend for consistency with this library and to be able to use [VError](https://www.npmjs.com/package/verror).

You may also use other elements exposed by this library in your tests -- Mostly likely [`Parcel`](./api/classes/parcel.html), [`generateRSAKeyPair`](./api/globals.html#generatersakeypair) and[ `issueNodeCertificate`](./api/globals.html#issuenodecertificate).

Everything else is likely to be unique to the binding you're implementing.

If you want to see what a binding implementation in Node.js looks like, have a look at [@relaycorp/relaynet-pohttp](https://github.com/relaycorp/relaynet-pohttp-js).
