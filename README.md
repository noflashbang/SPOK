# SPOK API

The Secure Platform Ops Kit (SPOK) API is divided into two main parts: the Client API (SPOKClientApi.h) and the Server API (SPOKServerApi.h).

Together, these APIs provide a comprehensive set of functions for managing and using Attestation Identity Keys (AIKs), performing cryptographic operations, and handling attestations. They are designed to be used in a client-server model, where the client performs operations and the server verifies and responds to those operations.

The SPOK API is licensed under the MIT License, which allows for free use, modification, and distribution of the software.

## SPOK Client API (SPOKClientApi.h)

The Client API provides functions for AIK (Attestation Identity Key) management, attestation, public key access, endorsement key access, challenge handling, quote and verify operations, SRK (Storage Root Key) access, user key addition, and TPM cryptographic operations.

### AIK Management

- `SPC_AIKCreate`: Creates an AIK.
- `SPC_AIKDelete`: Deletes an AIK.
- `SPC_AIKExists`: Checks if an AIK exists.

### AIK Attestation

- `SPC_AIKGetKeyAttestation`: Gets key attestation for an AIK.
- `SPC_AIKGetPlatformAttestation`: Gets platform (Boot Log) attestation for an AIK.

### AIK Public Key

- `SPC_AIKGetPublicKey`: Gets the public key of an AIK.

### Endorsement Key Access

- `SPC_GetEndorsementPublicKey`: Gets the endorsement public key (ekpublic) of the TPM device.

### AIK Challenge

- `SPC_AIKGetChallengeBinding`: Gets the challenge binding for an AIK.
- `SPC_AIKActivateChallenge`: Activates a challenge for an AIK.

### AIK Quote and Verify

- `SPC_GetBootLog`: Gets the boot log.
- `SPC_GetFilteredBootLog`: Gets the boot log filtered by PCR to include.
- `SPC_GetPCRTable`: Gets the PCR (Platform Configuration Registers) table.

### SRK Access

- `SPC_GetStorageRootKey`: Gets the storage root key.

### User Key Addition

- `SPC_PlatformImportWrappedKey`: Imports a wrapped key to the platform.
- `SPC_CreatePlatformKey`: Creates a platform key.
- `SPC_PlatformKeyExists`: Checks if a platform key exists.

### Cryptographic Operations

- `SPC_PlatformDecrypt`: Decrypts data using a platform key.
- `SPC_PlatformEncrypt`: Encrypts data using a platform key.
- `SPC_PlatformSign`: Signs data using a platform key.
- `SPC_PlatformVerifySignature`: Verifies a signature using a platform key.

## SPOK Server API

The Server API provides functions for AIK platform attestation, AIK TPM attestation, AIK key attestation, basic cryptographic operations, and key helpers.

### Attestation Cleanup

- `SPS_AttestationDestroy`: Destroys an attestation.

### AIK Platform Attestation

- `SPS_AIKPlatformAttest_Decode`: Obtains a handle to an AIK platform attestation.
- `SPS_AIKPlatformAttest_GetPCR`: Gets the PCR (Platform Configuration Registers) for an AIK platform attestation.
- `SPS_AIKPlatformAttest_GetTcgLog`: Gets the TCG log for an AIK platform attestation.
- `SPS_AIKPlatformAttest_Verify`: Verifies an AIK platform attestation.

### AIK TPM Attestation

- `SPS_AIKTpmAttest_Decode`: Obtains a handle to an AIK TPM attestation.
- `SPS_AIKTpmAttest_GetChallenge`: Gets the challenge for an AIK TPM attestation.
- `SPS_AIKAttest_Verify`: Verifies an AIK TPM attestation.

### AIK Key Attestation

- `SPS_AIKKeyAttest_Decode`: Obtains a handle to an AIK key attestation.
- `SPS_AIKKeyAttest_Verify`: Verifies an AIK key attestation.

### Basic Cryptographic Operations

- `SPS_Decrypt`: Decrypts data.
- `SPS_Encrypt`: Encrypts data.
- `SPS_Sign`: Signs data.
- `SPS_VerifySignature`: Verifies a signature.

### Key Helpers

- `SPS_GenerateRSAKeyPair`: Generates an RSA key pair.
- `SPS_WrapKeyForPlatformImport`: Wraps a key for platform import.
- `SPS_WrappedKeyName`: Gets the name of a wrapped key.
