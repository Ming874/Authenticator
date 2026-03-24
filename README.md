# Secure Authenticator

A professional-grade, high-security, and entirely client-side TOTP (Time-based One-Time Password) authenticator. Designed with a privacy-first philosophy, this application provides a seamless and secure experience for managing two-factor authentication (2FA) codes without relying on cloud services.

## Security Architecture

Secure Authenticator is built on a foundation of modern web security primitives to ensure that your sensitive data remains under your absolute control.

- **Hardware-Level Protection**: Leverages the **WebAuthn API** to gate access through device-native biometrics (FaceID, TouchID, or Android Biometrics). Your vault is only accessible after successful local authentication.
- **End-to-End Client-Side Encryption**: All TOTP secrets are encrypted using **AES-256-GCM** before being persisted. Encryption keys are never stored; they are derived at runtime using **PBKDF2** with a unique salt and high iteration counts.
- **Data Isolation**: Adheres to a strict **Content Security Policy (CSP)**. By setting `connect-src 'none'`, the application is mathematically incapable of transmitting your data to any external server.
- **Zero Cloud Footprint**: All account data is stored locally in the browser's **IndexedDB**. There are no accounts to create, no servers to trust, and no data to sync to the cloud.

## Key Features

- **PWA Excellence**: Fully compliant Progressive Web App. Installable on iOS, Android, and Desktop, providing a native-like experience with full offline functionality.
- **Intuitive Gesture-Based UX**:
    - **Swipe-to-Edit**: Effortlessly manage account labels with a natural left-swipe gesture on any card.
    - **One-Tap Copy**: Instantly copy your 6-digit code to the clipboard with a single tap.
- **Dynamic Viewport Optimization**: Utilizes modern CSS units (`100dvh`) to ensure a perfect, scroll-free interface across all mobile browsers and device orientations.
- **Precision TOTP Engine**: Real-time 30-second countdown with high-fidelity progress animations (30fps), ensuring you always know exactly when your code will rotate.
- **Minimalist Aesthetic**: Built with the "Inter" typeface and a clean, card-based UI that prioritizes readability and professional utility.

## Getting Started

1. **Deployment**: Host the static files on any HTTPS-enabled server.
2. **Setup**: Access the URL and follow the system prompt to register your device's biometric sensor.
3. **Management**:
    - Use the **Add (+)** button to manually input your Service Name and Base32 Secret Key.
    - **Swipe Left** on any card to reveal the Edit action for quick renaming.
    - **Tap** a card to copy the code.

## Technical Stack

- **Core**: Vanilla TypeScript/JavaScript (ES6+), Web Crypto API.
- **Storage**: IndexedDB (Encrypted persistence).
- **Security**: WebAuthn API, Web Cryptography API (SubtleCrypto).
- **Service Layer**: Service Worker for PWA lifecycle and offline caching.
- **UI/UX**: HTML5 Semantic Markup, CSS3 Custom Properties, Dynamic Viewport Handling.

## Important Security Notice

This application is a **Zero-Cloud** solution. Your data resides **exclusively** within your browser's local storage. Clearing your browser cache or losing your device will result in the permanent loss of your 2FA secrets. **Always maintain physical backups (Recovery Codes) for all services secured by this app.**

---
Created by [Ming Chen](https://mingchen.dev)
