# Third-party components

The root `LICENSE` covers this project's original code and documentation only.
The following components retain their own licenses. A source file's original
license notice takes precedence for that file; copying a component into this
repository does not relicense it.

| Component | Scope | License and source |
| --- | --- | --- |
| strongSwan Python VICI client | Vendored Python client modules where included | MIT; [upstream notice](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/python/LICENSE), copied in `third_party/licenses/VICI-MIT.txt` |
| strongSwan daemon, utilities, plugins and changes to upstream files | External build dependency; any included patch remains subject to the affected upstream file's terms | Upstream generally uses GPL-2.0-or-later, with file-specific exceptions; [upstream COPYING](https://github.com/strongswan/strongswan/blob/master/COPYING), copied in `third_party/licenses/strongSwan-GPL-2.0.txt` |
| OpenSSL 3.x | External cryptographic build/link dependency; not relicensed by this project | Apache-2.0; [upstream license](https://github.com/openssl/openssl/blob/master/LICENSE.txt), copied in `third_party/licenses/OpenSSL-Apache-2.0.txt` |
| pkgconf | External native build tool | Its permissive notice is retained in `native/licenses/pkgconf-COPYING.txt` |
| Sites Vite plugin | Copied web build tooling | MIT, Copyright 2026 OpenAI; retained in `web/scripts/vite/sites-vite-plugin.LICENSE` |
| shadcn Tailwind styles | Vendored web style source | MIT, Copyright 2023 shadcn; retained in `web/vendor/shadcn-tailwind-4.13.0.LICENSE.md` |

The standalone public-certificate/CRL verification helper is project source that
uses OpenSSL APIs. Its original code is covered by the root license. That does
not extend the root license to OpenSSL or grant permission to redistribute an
arbitrary linked binary without satisfying its components' licenses. The
repository does not include the original machine's compiled helper or its local
build manifest.

The VICI client may carry local timeout/transport changes. Those changes do not
remove its original copyright and MIT notice. Preserve that notice when
redistributing the client or substantial portions of it.

The supplied strongSwan build options, source patches, and version references
do not imply that the daemon itself is MIT licensed. If redistributing a built
strongSwan package, review the exact upstream source files, enabled plugins,
link dependencies, source-availability obligations and relevant upstream
linking exceptions for that build. This source publication makes no blanket
license-compatibility claim about every possible plugin or binary combination.

System tools and frameworks supplied by Apple are not distributed in this
repository. If adding other dependencies, preserve their notices and record
their source and license here.

Additional web dependencies are declared in `web/package.json` and its lockfile.
They are installed from their package registries, rather than copied from the
original machine's `node_modules`. Their own package notices and license terms
continue to apply to source and bundles built from them.
