# Code signing

Release builds of `BACnetExampleBSCHUB.exe` are signed with **Azure Artifact
Signing** from GitHub Actions. This is the same setup as
`chipkin-modbus-explorer`: GitHub OIDC logs in to Azure, so no certificate,
key or password is stored in GitHub.

## What the workflow does

In `.github/workflows/release.yml`, on a `vX.Y.Z` tag build only, the Windows
leg of the `build` job:

1. runs in the GitHub environment `release`
2. logs in to Azure with OIDC (`azure/login`)
3. signs `build/Release/BACnetExampleBSCHUB.exe` (SHA-256, RFC 3161 timestamp
   from `http://timestamp.acs.microsoft.com`)
4. checks the signature with `signtool verify /pa`

The smoke test, metrics and release package all use the signed executable.
The `release` job also publishes `SHA256SUMS.txt` for every release asset.

Pull requests and the Linux leg never sign and never use the `release`
environment. A tag build **fails** if signing isn't configured, so an unsigned
Windows binary can't be published by mistake.

## One-time setup

### Azure

Use the existing app registration that `chipkin-modbus-explorer` signs with.
It already holds the signing role on the `chipkin-signing` account.

1. Azure portal -> **Microsoft Entra ID** -> **App registrations** -> the
   GitHub signing app.
2. **Certificates & secrets** -> **Federated credentials** -> **Add
   credential**:
   - Scenario: **GitHub Actions deploying Azure resources**
   - Organization: `chipkin`
   - Repository: `BACnetProfileExample-B-SCHUB-CPP`
   - Entity type: **Environment** (not Tag)
   - Environment name: `release`
   - Name: `bacnet-b-schub-release`

   The subject must read
   `repo:chipkin/BACnetProfileExample-B-SCHUB-CPP:environment:release`.

Or with the Azure CLI:

```bash
az ad app federated-credential create --id <AZURE_CLIENT_ID> --parameters '{
  "name": "bacnet-b-schub-release",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:chipkin/BACnetProfileExample-B-SCHUB-CPP:environment:release",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

No new role assignment is needed if the app already has **Artifact Signing
Certificate Profile Signer** on the `chipkin-signing` account (or its
`chipkin-public-trust` profile).

### GitHub

In this repository's **Settings**:

1. **Environments** -> **New environment** -> `release`. Under **Deployment
   branches and tags**, choose **Selected branches and tags** and add the tag
   rule `v*`, so only release tags can use the signing credential.
2. **Secrets and variables** -> **Actions** -> **Secrets** (repository, or
   on the `release` environment). Use the same values as
   `chipkin-modbus-explorer`, found on the app registration's Overview page
   and the subscription:
   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`
   - `AZURE_SUBSCRIPTION_ID`
3. **Variables**:
   - `AS_ENDPOINT` = `https://wus3.codesigning.azure.net/`
   - `AS_SIGNING_ACCOUNT_NAME` = `chipkin-signing`
   - `AS_CERTIFICATE_PROFILE_NAME` = `chipkin-public-trust`

With the GitHub CLI (secret values are prompted for, not echoed):

```bash
R=chipkin/BACnetProfileExample-B-SCHUB-CPP
gh api -X PUT repos/$R/environments/release
gh secret set AZURE_CLIENT_ID -R $R
gh secret set AZURE_TENANT_ID -R $R
gh secret set AZURE_SUBSCRIPTION_ID -R $R
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
| `azure/login`: *Not all values are present* | A `AZURE_*` secret is missing, or it's an environment secret on an environment other than `release`. |
| Signing: *403 Forbidden* | The app lacks the Artifact Signing Certificate Profile Signer role on the account or profile. |
| The job waits for approval | The `release` environment has required reviewers. Approve the run, or remove the rule. |
