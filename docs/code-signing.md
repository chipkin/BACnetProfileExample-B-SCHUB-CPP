# Code signing

Release builds of `BACnetExampleBSCHUB.exe` are signed with **Azure Artifact
Signing** from GitHub Actions. This is the same setup as
`chipkin-modbus-explorer`: GitHub OIDC logs in to Azure, so no certificate,
key or password is stored in GitHub.

## What the workflow does

In `.github/workflows/release.yml`, on a `vX.Y.Z` tag build only, the Windows
leg of the `build` job:

1. runs in the GitHub environment `release`
2. **first**, before checkout and the build: checks the `AS_*` variables,
   logs in to Azure with OIDC (`azure/login`), and checks that a code-signing
   token can be issued. A configuration problem fails the run in seconds.
3. after the build, signs `build/Release/BACnetExampleBSCHUB.exe` (SHA-256,
   RFC 3161 timestamp from `http://timestamp.acs.microsoft.com`)
4. checks the signature with `signtool verify /pa`

The smoke test, metrics and release package all use the signed executable.
The `release` job also publishes `SHA256SUMS.txt` for every release asset.

Pull requests and the Linux leg never sign and never use the `release`
environment. A tag build **fails** if signing isn't configured, so an unsigned
Windows binary can't be published by mistake.

## One-time setup

### Azure

Use the app registration **`github-trusted-signing-bacnet-explorer`**
(client ID `8343d7c0-0263-44df-b5be-baab0d48ab48`), the one
`chipkin-modbus-explorer` and `chipkin-bacnet-explorer` sign with. It holds the
**Artifact Signing Certificate Profile Signer** role on
`chipkin-signing/chipkin-public-trust`. (The similarly named
`github-actions-artifact-signing` app has no Azure roles and can't sign.)

1. Azure portal -> **Microsoft Entra ID** -> **App registrations** ->
   `github-trusted-signing-bacnet-explorer`.
2. **Certificates & secrets** -> **Federated credentials** -> **Add
   credential**:
   - Scenario: **GitHub Actions deploying Azure resources**
   - Organization: `chipkin`
   - Repository: `BACnetProfileExample-B-SCHUB-CPP`
   - Entity type: **Environment** (not Tag)
   - Environment name: `release`
   - Name: `bacnet-b-schub-release`

   The subject must read
   `repo:chipkin/BACnetProfileExample-B-SCHUB-CPP:environment:release`. If
   the portal asks for an Organization ID and Repository ID it builds an
   ID-based subject (`repo:chipkin@14987761/...@1277739699:...`), which this
   repository does not send - change the subject to the form above.

Or with the Azure CLI:

```bash
az ad app federated-credential create --id 8343d7c0-0263-44df-b5be-baab0d48ab48 --parameters '{
  "name": "bacnet-b-schub-release",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:chipkin/BACnetProfileExample-B-SCHUB-CPP:environment:release",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

No new role assignment is needed: the app already has the signing role.

### GitHub

In this repository's **Settings**:

1. **Environments** -> **New environment** -> `release`. Under **Deployment
   branches and tags**, choose **Selected branches and tags** and add the tag
   rule `v*`, so only release tags can use the signing credential.
2. **Environments** -> `release` -> **Environment secrets**:
   - `AZURE_CLIENT_ID` = `8343d7c0-0263-44df-b5be-baab0d48ab48`
   - `AZURE_TENANT_ID` = the Directory (tenant) ID on the app's Overview page
   - `AZURE_SUBSCRIPTION_ID` = `0f1f7ccd-01c1-4ee4-88c4-3fa5acc43114`
     ("CodeSiging", the subscription holding `chipkin-signing`)
3. **Variables**:
   - `AS_ENDPOINT` = `https://wus3.codesigning.azure.net/`
   - `AS_SIGNING_ACCOUNT_NAME` = `chipkin-signing`
   - `AS_CERTIFICATE_PROFILE_NAME` = `chipkin-public-trust`

With the GitHub CLI (secret values are prompted for, not echoed):

```bash
R=chipkin/BACnetProfileExample-B-SCHUB-CPP
gh api -X PUT repos/$R/environments/release
gh secret set AZURE_CLIENT_ID -R $R --env release
gh secret set AZURE_TENANT_ID -R $R --env release
gh secret set AZURE_SUBSCRIPTION_ID -R $R --env release
gh variable set AS_ENDPOINT -R $R --body "https://wus3.codesigning.azure.net/"
gh variable set AS_SIGNING_ACCOUNT_NAME -R $R --body "chipkin-signing"
gh variable set AS_CERTIFICATE_PROFILE_NAME -R $R --body "chipkin-public-trust"
```

The `v*` tag rule on the environment is easiest to add in the web UI.

## Checking a release

Windows (PowerShell):

```powershell
Get-AuthenticodeSignature .\BACnetExampleBSCHUB.exe | Format-List Status, SignerCertificate
Get-FileHash .\BACnetExampleBSCHUB.exe -Algorithm SHA256
```

Linux:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## Troubleshooting

| Error in the tag build | Fix |
|---|---|
| `Missing repo variable AS_...` | Add the three `AS_*` variables. |
| `azure/login`: *No matching federated identity record found* | The federated credential's subject doesn't match. It must be `repo:chipkin/BACnetProfileExample-B-SCHUB-CPP:environment:release`. |
| `azure/login`: *No subscriptions found* | The app behind `AZURE_CLIENT_ID` has no role in `AZURE_SUBSCRIPTION_ID`. Use `github-trusted-signing-bacnet-explorer` and the CodeSiging subscription. |
| `azure/login`: *Not all values are present* | A `AZURE_*` secret is missing, or it's an environment secret on an environment other than `release`. |
| Signing: *403 Forbidden* | The app lacks the Artifact Signing Certificate Profile Signer role on the account or profile. |
| The job waits for approval | The `release` environment has required reviewers. Approve the run, or remove the rule. |
