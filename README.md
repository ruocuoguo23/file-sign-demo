# FileSigner with OpenPubkey

This project demonstrates how to sign and verify local files using [OpenPubkey](https://github.com/openpubkey/openpubkey), with a focus on solving the **OIDC public key rotation** problem.

## 🔍 Background

[OpenPubkey](https://github.com/openpubkey/openpubkey) provides a way to bind public keys to OIDC identities (like Google accounts) using PKToken. However, one limitation is that **OIDC providers may rotate their public keys**, which can cause verification failures for previously issued tokens.

## ✅ Solution

This project extends OpenPubkey by:

- Signing **local files** using OpenPubkey.
- Computing the **SHA256 digest** of the file and signing that digest.
- Saving the **PKToken**, **signature**, and the **OIDC public key (as JWK)** to local files at signing time.
- During verification, loading the saved public key to **verify the signature offline**, even if the OIDC provider has rotated its keys.

## 📦 Features

- 🔐 Sign any local file using your OIDC identity.
- 🧾 Store signature, PKToken, and public key locally.
- ✅ Verify file integrity and signature offline using cached public key.
