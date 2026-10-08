# Code signing

The Windows executable in each release (`BACnetExampleBSCHUB.exe`) is signed
with **Azure Artifact Signing** from GitHub Actions. GitHub OIDC logs in to
Azure, so no certificate, key or password is stored in GitHub.

## What the workflow does

In `.github/workflows/release.yml`, on a `vX.Y.Z` tag build only, the Windows
leg of the `build` job:

1. runs in the GitHub environment `release`;
2. **first**, before checkout and the build: checks the `AS_*` variables,
   logs in to Azure with OIDC (`azure/login`), and checks that a code-signing
   token can be issued, so a configuration problem fails the run in seconds;
3. after the build, signs the executable (SHA-256, RFC 3161 timestamp from
   `http://timestamp.acs.microsoft.com`) and checks it with
   `signtool verify /pa`.

The smoke test, the tests and the release zip all use the signed executable.
Pull requests and the Linux leg never sign and never use the `release`
environment. A tag build **fails** if signing isn't configured, so an unsigned
Windows binary can't be published by mistake. The `release` job publishes
`SHA256SUMS.txt` for every release asset.

## One-time setup

**Azure** - the app registration `github-trusted-signing-bacnet-explorer`
(client ID `8343d7c0-0263-44df-b5be-baab0d48ab48`, which holds the Artifact
Signing Certificate Profile Signer role on
`chipkin-signing/chipkin-public-trust`) needs a federated credential for this
repository:

- Organization `chipkin` (ID `14987761`), repository
  `BACnetProfileExample-B-SCHUB-CPP` (ID `1409496357`), entity type
  **Environment**, environment `release`.
- Subject:
  `repo:chipkin@14987761/BACnetProfileExample-B-SCHUB-CPP@1409496357:environment:release`
  (this repository sends GitHub's ID-based OIDC subject; check with
  `gh api repos/chipkin/BACnetProfileExample-B-SCHUB-CPP/actions/oidc/customization/sub`).

```bash
az ad app federated-credential create --id 8343d7c0-0263-44df-b5be-baab0d48ab48 --parameters '{
  "name": "bacnet-profile-example-b-schub-cpp-release",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:chipkin@14987761/BACnetProfileExample-B-SCHUB-CPP@1409496357:environment:release",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

**GitHub** - in this repository's settings:

1. Environment `release`, limited to the tag rule `v*`.
2. Environment secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID`.
3. Repository variables `AS_ENDPOINT` (`https://wus3.codesigning.azure.net/`),
   `AS_SIGNING_ACCOUNT_NAME` (`chipkin-signing`),
   `AS_CERTIFICATE_PROFILE_NAME` (`chipkin-public-trust`).
4. The repository secret `CAS_STACK_PAT` (read access to the private CAS
   BACnet Stack submodule), as for every example in the series.

## Checking a release

```powershell
Get-AuthenticodeSignature .\BACnetExampleBSCHUB.exe | Format-List Status, SignerCertificate
```

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```
