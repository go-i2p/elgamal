# elgamal

A focused, pure-Go implementation of the ElGamal cryptographic system.

## Overview

This library provides a minimal, security-focused implementation of ElGamal encryption and decryption in pure Go. It is designed for stability and correctness, with no external dependencies.

## Features

- Pure Go implementation with no C dependencies
- Minimal API surface for reduced attack vectors
- Well-tested cryptographic primitives
- Comprehensive input validation and error handling

## Security Notice

This implementation is intended for specific use cases where ElGamal is required. For general-purpose public key cryptography, consider using established alternatives like RSA or elliptic curve cryptography from the standard library.

**Important:** This implementation uses `math/big` for arbitrary-precision arithmetic, which is not constant-time. The library may be vulnerable to timing side-channel attacks. Use appropriate security measures when deploying in sensitive environments.

## Status

This library is in maintenance mode, focusing on stability and security updates.

