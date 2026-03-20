# Secure Vault: Offline Biometric Authenticator

A high-security, privacy-first, and fully offline Web-based TOTP (Time-based One-Time Password) authenticator. This project implements a secure alternative to Google Authenticator that runs entirely in the browser using modern Web APIs.

## 1. Core Architecture & Technical Principles

### 1.1 TOTP Algorithm (RFC 6238)
The core generation logic follows the standard TOTP protocol:
1.  **Time Normalization**: Retrieves the current Unix timestamp, divides it by the 30-second step interval, and floors the result to obtain the counter `T`.
2.  **Secret Decoding**: Decodes the Base32-encoded seed into a raw byte stream `K`.
3.  **HMAC-SHA1 Computation**: Performs an HMAC-SHA1 hash using `K` as the key and `T` (encoded as an 8-byte big-endian integer) as the message.
4.  **Dynamic Truncation**: Extracts a 4-byte sequence from the hash based on the last nibble's offset and converts it to a 31-bit integer.
5.  **Modulo Operation**: Calculates the result modulo 1,000,000 to produce a 6-digit code.

### 1.2 Zero-Knowledge Storage Security
*   **Encryption Standard**: Employs `AES-256-GCM` for authenticated encryption of all sensitive seeds.
*   **Key Derivation**: Implements a zero-knowledge architecture where the Master Key is never stored. After successful WebAuthn verification, a symmetric key is derived via `PBKDF2` using a unique salt and hardware-backed entropy.
*   **Persistence**: Utilizes `IndexedDB` for localized storage of `{ id, label, encrypted_seed, iv, salt }`.

---

## 2. Implementation Framework

### UI/UX & Responsive Design
*   **Stack**: Native HTML5, CSS3 (Grid & Flexbox).
*   **Visual States**: 
    *   **Lock Screen**: Minimalist biometric authentication interface.
    *   **Vault View**: Card-based layout with real-time TOTP generation and synchronized progress indicators.
*   **Interaction**: Integrated "One-tap Copy" functionality via the Clipboard API.

### Cryptographic Engine
*   **Web Crypto API**: Leveraging `window.crypto.subtle` for high-performance, hardware-accelerated HMAC and AES operations.
*   **Base32 Implementation**: A custom, lightweight decoder for transforming industry-standard secrets into byte arrays.

### Biometric Integration (WebAuthn)
*   **Hardware-Backed Security**: Uses `navigator.credentials` to interface with system-level authenticators (Touch ID, Face ID, Windows Hello).
*   **State Management**: Cryptographic keys are held only in volatile memory and are purged upon session termination or manual lock.

### QR Code Scanning
*   **Camera Integration**: Utilizes `navigator.mediaDevices.getUserMedia` for real-time video streaming.
*   **Edge Processing**: Integrates `jsQR` for client-side barcode decoding, ensuring no image data is transmitted over the network.

### Progressive Web App (PWA)
*   **Service Worker**: Implements an aggressive caching strategy for 100% offline availability.
*   **Update Lifecycle**: Advanced service worker management to ensure seamless background updates and immediate activation.

---

## 3. Security Evaluation
| Threat Vector | Mitigation Strategy |
| :--- | :--- |
| **XSS Attacks** | Strict Content Security Policy (CSP) prohibiting inline scripts and external domain requests. |
| **Physical Theft** | All data in IndexedDB is AES-GCM encrypted; decryption requires biometric hardware verification. |
| **Data Leakage** | Zero-Knowledge architecture ensures seeds never leave the local device environment. |

---

## 4. Key Deliverables
*   **Autonomous Operation**: Zero external dependencies or API calls during runtime.
*   **Biometric Speed**: Near-instant vault access via native device authentication.
*   **Visual Precision**: Synchronized countdown timers with smooth 60fps UI updates.
*   **Privacy Centric**: Full compliance with "Privacy by Design" principles.
