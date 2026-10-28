# TorProxy Mobile (Android)

This is a native Android app module alongside the existing PySide6 desktop app. It does not attempt to package Qt/PySide6 for Android.

## Embedded Tor and transports

TorProxy Mobile uses version-pinned upstream Android libraries rather than copying random binaries into this repository:

- Guardian Project Tor Android 0.4.9.14 supplies the native Tor daemon and Android TorService, including platform-specific libtor binaries.
- Guardian Project jtorctl 0.4.5.7 provides the Tor control protocol API.
- IPtProxy 5.7.0 supplies Android-compatible pluggable transports: obfs4/Lyrebird, WebTunnel, meek-lite and DNSTT.

Dependencies are resolved from Maven Central and the Guardian Project Maven repository. The app's own state and IPtProxy state stay in app-private storage. The app does not bundle a Tor Expert Bundle ZIP and does not try to run a desktop Linux or Windows executable on Android.

## Current behavior

- Start and stop the embedded Tor daemon.
- Show Tor's own bootstrap status and local proxy endpoints.
- Configure direct Tor or a pluggable transport with matching user-provided bridge lines.
- Check the exit IP through Tor's SOCKS listener. The check has no direct-network fallback.
- Send Tor's NEWNYM control signal. Tor may keep the same visible exit IP; NEWNYM is not a guarantee of a new address.
- Store bridge lines locally on the device.

The exposed listeners are loopback-only. When running, the default ports are SOCKS 9050 and HTTP CONNECT 8118; the app displays the ports reported by Tor when available.

## Important routing limitation

This first Android implementation exposes local proxy endpoints for apps that can be configured to use a SOCKS or HTTP CONNECT proxy. It does **not** yet include an Android VpnService/tun2socks layer and does not automatically redirect all phone traffic. Android does not offer a normal app the same system-wide proxy switch available on desktop systems; whole-device routing requires a separate VPN implementation, explicit user approval, and careful DNS/IPv6 handling. The UI calls out this limitation instead of implying that every app is protected.

A custom bridge line must match the selected transport. For example, an obfs4 record must start with the token obfs4; a WebTunnel record must start with webtunnel. Obtain bridge records from a source you trust and keep them private if required by your threat model. No fixed bridge addresses are hard-coded.

## Build

Requirements: JDK 17, Android SDK platform 37, and Gradle 9.6.0.

From the repository root:

1. Open the android directory in Android Studio, or change into it in a terminal.
2. Install Android platform 35 and build tools 36.0.0 using SDK Manager.
3. Run: gradle --no-daemon :app:testDebugUnitTest :app:assembleDebug

The debug APK is produced at android/app/build/outputs/apk/debug/app-debug.apk.

Pushing changes to the Android branch starts the Android GitHub Actions workflow. It runs local unit tests, assembles the APK and uploads the APK as a workflow artifact. A successful build is not the same as a tested on-device connection; test on a physical Android device and inspect logcat before treating it as production-ready.

## Upstream references and licenses

- Tor Android: https://github.com/guardianproject/tor-android
- IPtProxy: https://github.com/tladesignz/IPtProxy

The Tor Android dependency is distributed under its upstream license; IPtProxy is MIT-licensed. Their binaries are obtained via the declared Maven dependencies; this repository does not copy or repackage their source trees.
