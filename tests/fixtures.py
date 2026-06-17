#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Realistic test fixtures for the Fractum test suite.

Content mirrors the actual use cases documented in the README:
  - Bitwarden vault exports
  - Hardware wallet seed phrases (BIP-39)
  - Root CA / SSH private keys
  - Break-glass emergency credentials
  - Legal / financial documents
"""

# ── Bitwarden vault export (unencrypted JSON) ─────────────────────────────────
# Mirrors what the README shows: fractum encrypt passwords-export.csv
#                                 --label "bitwarden-backup"

BITWARDEN_VAULT_EXPORT = b"""\
{
  "encrypted": false,
  "folders": [
    {"id": "72cba048-1a2b-3c4d-5e6f-7a8b9c0d1e2f", "name": "Infrastructure"},
    {"id": "83dcb159-2b3c-4d5e-6f7a-8b9c0d1e2f3a", "name": "Finance"}
  ],
  "items": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "folderId": "72cba048-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
      "type": 1,
      "name": "GitHub -- katvio-org (production)",
      "notes": "Main organisation account. Rotate every 90 days.",
      "login": {
        "username": "alice.martin@katvio.io",
        "password": "p@ssW0rd#katvio!2025",
        "passwordRevisionDate": "2025-01-14T09:23:11.000Z",
        "uris": [{"match": null, "uri": "https://github.com/katvio"}],
        "totp": "JBSWY3DPEHPK3PXP"
      }
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "folderId": "72cba048-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
      "type": 1,
      "name": "AWS -- root account (break-glass only)",
      "notes": "Root account. Requires 2-of-3 board approval. Last used 2024-11-03.",
      "login": {
        "username": "root@katvio.io",
        "password": "Aws#R00t!breakGlass_2025",
        "passwordRevisionDate": "2025-02-01T08:00:00.000Z",
        "uris": [{"match": null, "uri": "https://console.aws.amazon.com"}],
        "totp": null
      }
    },
    {
      "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "folderId": "72cba048-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
      "type": 1,
      "name": "PostgreSQL -- production",
      "notes": "Main application database. Read-replica password in separate entry.",
      "login": {
        "username": "app_user",
        "password": "Pg#admin!s3cr3t@prod2025",
        "passwordRevisionDate": "2025-01-03T10:15:00.000Z",
        "uris": [{"match": null, "uri": "postgresql://db.prod.katvio.io:5432/katvio_prod"}],
        "totp": null
      }
    },
    {
      "id": "d4e5f6a7-b8c9-0123-defa-234567890123",
      "folderId": "83dcb159-2b3c-4d5e-6f7a-8b9c0d1e2f3a",
      "type": 1,
      "name": "Stripe -- live secret key",
      "notes": "Do not share outside Finance. Webhook secret in next entry.",
      "login": {
        "username": "admin@katvio.io",
        "password": "sk_fake_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX",
        "passwordRevisionDate": "2025-01-20T14:00:00.000Z",
        "uris": [{"match": null, "uri": "https://dashboard.stripe.com"}],
        "totp": null
      }
    }
  ]
}
"""

# ── Hardware wallet seed phrase (BIP-39, 24 words) ────────────────────────────
# These are the "abandon" test words from the BIP-39 spec -- not a real wallet.
# Used to simulate encrypting a cold-storage seed phrase.

HARDWARE_WALLET_SEED = b"""\
# Trezor Model T -- cold wallet seed phrase
# Created: 2025-01-15 | Last verified: 2025-02-28
# STORE THIS FILE OFFLINE ONLY -- NEVER UPLOAD TO ANY SERVER
#
# BIP-39 mnemonic (24 words, 256-bit entropy):

abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across act action actor actress actual

# Derivation path: m/44'/0'/0' (Bitcoin mainnet, account 0)
# Extended public key (xpub) for verification only:
# xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz
#
# Fingerprint: 0x3A2F7B9C
# Balance at creation: 0.42180000 BTC
"""

# ── Root CA private key (illustrative PEM -- not a real key) ─────────────────
# Matches the README use case: "Root CA / PKI private keys"

ROOT_CA_PRIVATE_KEY = b"""\
-----BEGIN ENCRYPTED PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8A3F2D1C9E7B4A6F2D8C1E3B5A7F9D2C

MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAIITzGxkRPlxNsCAgg
AAgEQMBQGCCqGSIb3DQMHBAgVSYA2gv2JMgSCBMCFmL2nKtP8eA4jQs7mYxkb9W
Zr3bXuVL6TkNc2dGHwPqR1mJsOeA8tF5Yv3BwCkD0Xf7nQiE4RaT2hS9MpUjVo
Gv6LdKzWBsNfYE3cXuIA2pT8mQrV5LkHb0nJ9AdP4CsE1Fo7gWqY6txDZiU3Ke
kR3bT9xFzL2cMsA8pUjG4vE6qNdY0hW7iK1nB5oC3lQ2tH8wP9rXeZ4yS6mJ7u
Lp1oFqR8wZvC5aBdMkTyHsXn2eUcGjPiV7OzNqKbYlDfE4WgJ9mSuQ6hTsA3Rv
-----END ENCRYPTED PRIVATE KEY-----

# CA Certificate fingerprint SHA-256:
# FA:3B:2C:8D:1E:9F:4A:7B:6C:5D:3E:2F:1A:0B:9C:8D:7E:6F:5A:4B:3C:2D:1E:0F:9A:8B:7C:6D:5E:4F:3A
# Issuer: CN=Katvio Root CA, O=Katvio SAS, C=FR
# Valid: 2025-01-01 to 2035-01-01
"""

# ── Break-glass emergency credentials ─────────────────────────────────────────
# "Emergency recovery credentials" per the README

BREAK_GLASS_CREDENTIALS = b"""\
# KATVIO -- BREAK-GLASS EMERGENCY CREDENTIALS
# Classification: TOP SECRET / RESTRICTED
# Procedure: Requires physical presence of 2 of 3 designated officers
# Last audited: 2025-02-14 by Alice Martin (CTO) + Thomas Dubois (CRO)
#
# === PRODUCTION INFRASTRUCTURE ===

AWS_ROOT_ACCOUNT=root@katvio.io
AWS_ROOT_PASSWORD=Aws#R00t!Emergency_2025#Kv
AWS_MFA_SEED=JBSWY3DPEHPK3PXP2JBSWY3DPEHPK3PXP

CLOUDFLARE_GLOBAL_API_KEY=7c5dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CLOUDFLARE_ACCOUNT_EMAIL=ops@katvio.io

GITHUB_ORG_RECOVERY_CODE=abcd-1234-efgh-5678-ijkl-9012
GITHUB_ORG_BACKUP_CODES=mnop-3456-qrst-7890-uvwx-1234

# === DNS / DOMAIN REGISTRAR ===

GANDI_RECOVERY_KEY=GANDI-XXXX-XXXX-XXXX-XXXX
KATVIO_IO_AUTH_CODE=KtvIo#DnS!2025Transfer

# === ENCRYPTION / SIGNING KEYS ===

CODE_SIGNING_KEY_PASSPHRASE=S1gn#Kv2025!Deploy
PRODUCTION_DEPLOY_SSH_PASSPHRASE=D3pl0y#SSH!Prod2025

# === INCIDENT CONTACTS ===
# Primary: Alice Martin, CTO -- +33 6 XX XX XX XX
# Secondary: Romain Petit, VP Eng -- +33 6 XX XX XX XX
# Legal: Sophie Bernard -- +33 1 XX XX XX XX
"""

# ── Production .env credentials file ─────────────────────────────────────────

ENV_CREDENTIALS = b"""\
# Production environment -- CONFIDENTIAL
# Last rotated: 2025-01-17 by Alice Martin <alice@katvio.io>
# Next rotation due: 2025-04-17
# DO NOT COMMIT -- encrypt with Fractum before storing

DATABASE_URL=postgresql://app_user:Pg#admin!s3cr3t@2025@db.prod.katvio.io:5432/katvio_prod
REPLICA_URL=postgresql://app_ro:Rd#only!2025@replica.katvio.io:5432/katvio_prod
REDIS_URL=redis://:R3dis#s3cr3t!2025@cache.prod.katvio.io:6379/0

STRIPE_SECRET_KEY=sk_fake_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX
STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SENTRY_DSN=https://abcdef1234567890@o123456.ingest.sentry.io/1234567

JWT_SECRET=a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0aa
ENCRYPTION_KEY=4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5
"""

# ── Quarterly financial report ─────────────────────────────────────────────────

QUARTERLY_REPORT = b"""\
CONFIDENTIEL -- Rapport financier T4 2025
Katvio SAS -- Usage interne uniquement
Prepare par: Sophie Bernard (Head of Finance)
Approuve par: Alice Martin (CEO) le 2026-01-10

Date,Departement,Produit,Revenus EUR,Depenses EUR,Marge EUR,Marge %
2025-10-31,Engineering,Fractum Enterprise,143000,52000,91000,63.6%
2025-10-31,Sales,Fractum Pro,287000,94000,193000,67.2%
2025-10-31,Operations,Support Premium,68500,41200,27300,39.9%
2025-11-30,Engineering,Fractum Enterprise,159000,55000,104000,65.4%
2025-11-30,Sales,Fractum Pro,312000,98000,214000,68.6%
2025-11-30,Operations,Support Premium,74200,43100,31100,41.9%
2025-12-31,Engineering,Fractum Enterprise,178000,58000,120000,67.4%
2025-12-31,Sales,Fractum Pro,398000,112000,286000,71.9%
2025-12-31,Operations,Support Premium,89700,47800,41900,46.7%
TOTAL T4,,Fractum Enterprise,480000,165000,315000,65.6%
TOTAL T4,,Fractum Pro,997000,304000,693000,69.5%
TOTAL T4,,Support Premium,232400,132100,100300,43.2%
GRAND TOTAL T4,,,1709400,601100,1108300,64.8%
"""

# ── Employee payroll export ────────────────────────────────────────────────────

PAYROLL_EXPORT = b"""\
# Katvio SAS -- Export paie T4 2025
# CONFIDENTIEL -- Transmission via Fractum obligatoire
# Genere le 2026-01-03 par comptabilite@katvio.io

Matricule,Nom,Prenom,Poste,Departement,Salaire Brut EUR,Prime EUR,Date Entree
EMP-1042,Martin,Alice,Lead Engineer,Engineering,78500,12000,2022-03-14
EMP-1043,Petit,Romain,Senior Backend Engineer,Engineering,68000,8500,2023-01-09
EMP-1051,Moreau,Claire,Account Executive,Sales,52000,18400,2022-08-22
EMP-1067,Dubois,Thomas,DevOps Engineer,Engineering,72000,9000,2023-06-01
EMP-1089,Bernard,Sophie,Head of Finance,Finance,85000,22000,2021-11-15
EMP-1102,Leclerc,Marc,Product Manager,Product,69500,11000,2023-09-18
EMP-1115,Rousseau,Camille,Frontend Engineer,Engineering,64000,7500,2024-01-15
EMP-1128,Fontaine,Nicolas,Sales Engineer,Sales,58500,14200,2024-03-01
"""
