# Original release-generation implementation

`original-freeze.py` and `original-release-builder.py` preserve the author's
actual source-freeze and release-assembly implementation. The CLI entry is
disabled in this export; function bodies are retained for adaptation/review.
The generated root installer and byte-embedded update scripts are not included.

These files originally ran in a larger private workspace and read:

| Historical input | Non-secret metadata retained here |
|---|---|
| v8 runtime tree and its manifest | `../compat/v8-runtime-manifest.json` |
| v8 integration harness and its manifest | `../compat/v8-harness-manifest.json` |
| v9 installer `PAYLOAD` constant | `../compat/v9-payload-manifest.json` |
| predecessor control resource map | `../compat/historical-control-manifests.json` |

The paths and hash guards in the original functions document that historical
layout. They have **not** been made into a new-host installer. Old runtime
versions, installed receipts, CA material, and personal state are not recreated
by the exported manifests. Merely putting a file at an old path does not meet
the deployment's trust/ownership requirements.

To adapt the original assembler, replace its historical-tree inputs with an
explicitly reviewed compatibility manifest policy, regenerate current-source
bindings, rebuild the native CRL helper, and implement fresh PKI/system
installation separately. Do not skip existing guard failures or fabricate
successful history. The original assembly algorithm and templates are present
so these changes can be reviewed against the actual implementation.

For the self-contained, inert source package supported by this checkout, use:

```sh
python3 -I -B server/tools/build_reference.py --output build/reference-server
```
