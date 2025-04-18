# Portfolio Project

Overview:
KeyManager is a key management system designed to securely handle cryptographic keys throughout their lifecycle. The library provides a clean API for key generation, storage, retrieval, rotation, and destruction, while maintaining security best practices.

Features:
Key Generation - Create AES-256 encryption keys with custom identifiers and access levels
Key Storage - Securely store keys in a Java KeyStore with password protection
Key Retrieval - Retrieve keys along with their associated metadata
Key Rotation - Automatically rotate keys to maintain security
Key Destruction - Securely destroy keys when they are no longer needed
Access Control - Find keys by access level for permission-based operations
Key Verification - Verify key signatures using public keys
Expired Key Cleanup - Automatically remove keys that have passed their expiration date
Documentation - Export detailed key logs for documentation and auditing

Metadata Structure:
Each key in the KeyManager system has associated metadata:

Index 0: Key ID (String)
Index 1: Timestamp of creation (String representation of milliseconds)
Index 2: Access information (String)
Index 3: Digital signature (Base64-encoded String)
