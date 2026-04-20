# Contributing to dart_signal_protocol

Thank you for considering contributing! This library was extracted
from a private project and is being released as open source so that
the community can benefit from and improve it. All contributions are
welcome.

## Quick start

1. Fork the repository.
2. Clone your fork: `git clone https://github.com/<your-username>/dart-signal-protocol.git`
3. Create a feature branch: `git checkout -b feature/my-improvement`
4. Make your changes.
5. Run `dart analyze` to check for issues.
6. Run `dart test` (once tests are added).
7. Commit with a clear message (see [Commit messages](#commit-messages)).
8. Push to your fork and open a Pull Request.

## What we particularly welcome

This library is alpha-quality and there are many areas where help is
needed. Some particularly valuable contributions:

### High priority

- **Security review** of any algorithm in `lib/src/`. The author is
  not a cryptography expert. Even a careful read with a comment like
  "this looks fine" or "this looks suspicious, here's why" is valuable.
- **Wire format compatibility tests** — verify that messages produced
  by this library can be decrypted by the official libsignal, and vice
  versa. This is the single most important thing missing right now.
- **Unit tests** — coverage is currently very low. Tests for X25519,
  HKDF, X3DH, Double Ratchet, Sender Key would all be welcome.
- **Side-channel analysis** — identify any timing-sensitive operations
  that could leak key material under VM/JIT execution.

### Medium priority

- **API improvements** that make the library easier to use without
  compromising security.
- **Documentation** — dartdoc comments, examples, architecture notes.
- **Performance** — benchmarks and optimizations (without weakening
  security).

### Low priority (but welcome)

- **Sealed Sender** implementation.
- **PNI (Phone Number Identity)** implementation.
- **Storage layer reference implementations** (e.g., in-memory store
  for tests).

## What we will not accept

- Changes that weaken security guarantees (e.g., removing the
  small-subgroup attack check, accepting unsigned prekeys, disabling
  AEAD binding).
- Native dependencies (Platform Channels, FFI, native libraries).
  This library's value is being Pure Dart with zero native code.
- Telemetry, analytics, or any code that exfiltrates data.
- Changes to the license without prior discussion.

## Code style

- Follow the [Effective Dart Style Guide](https://dart.dev/effective-dart/style).
- Run `dart format lib/ test/ example/` before committing.
- Run `dart analyze` and fix any issues.
- File names: `snake_case.dart`.
- Class names: `UpperCamelCase`.
- Variables and functions: `lowerCamelCase`.
- Constants: `lowerCamelCase` (Dart convention, not `UPPER_SNAKE_CASE`).
- Indentation: 2 spaces.
- Maximum line length: 80 characters (Dart default).

### File headers

Each file should have a header comment in the following format:

```dart
/// @file        filename.dart
/// @description One-line description of what this file does.
/// @author      Your Name
/// @company     (optional)
/// @created     YYYY-MM-DD
/// @lastUpdated YYYY-MM-DD
///
/// @functions
///  - functionName(): description
```

### Logging

Do not import `package:flutter/foundation.dart`. The library is
intended to work in pure Dart environments. Use the local
`logger.dart` facade if you need debug output.

```dart
import 'logger.dart';

debugPrint('[X3DH] Computing shared secret');
```

By default, `debugPrint` is a no-op. Users can register a callback
via `setSignalProtocolLogger()` to receive messages.

**Never log key material, plaintext, or any cryptographically sensitive
state**, even at debug level.

## Commit messages

We use a simplified [Conventional Commits](https://www.conventionalcommits.org/)
format:

```
type(scope): subject

body (optional)
```

**Types**:
- `feat`: new feature
- `fix`: bug fix
- `refactor`: code change that neither fixes a bug nor adds a feature
- `docs`: documentation only
- `test`: adding or fixing tests
- `chore`: build, dependencies, tooling
- `perf`: performance improvement
- `security`: security fix or hardening

**Scopes** (optional): `x3dh`, `double-ratchet`, `sender-key`, `hkdf`,
`x25519`, `prekey`, `service`, `tests`, `docs`, etc.

**Examples**:

```
feat(sender-key): add multi-state record with 5 generations

Allows decryption of messages encrypted with previous sender keys
during key rotation, preventing race conditions when a member is
removed from a group.
```

```
fix(x25519): reject all-zero DH outputs

Mitigates small-subgroup attacks by rejecting public keys that
produce a zero shared secret.
```

```
docs: clarify alpha status in README
```

## Pull request guidelines

- **One logical change per PR.** If you are fixing two unrelated
  bugs, please open two PRs.
- **Describe what and why.** A short description of the change and
  the reasoning behind it.
- **Reference issues.** If your PR closes an issue, write
  `Closes #42` in the description.
- **Tests when applicable.** If you are fixing a bug, add a
  regression test. If you are adding a feature, add tests covering
  it.
- **Keep PRs reasonably small.** Large PRs are hard to review.

## Reporting bugs

For non-security bugs, please open a GitHub issue with:

- A description of the unexpected behavior.
- Steps to reproduce (a minimal code snippet is ideal).
- Expected vs actual behavior.
- Dart SDK version, OS, and any relevant environment details.

## Reporting security vulnerabilities

**Please do not open a public GitHub issue for security
vulnerabilities.**

Instead, please email the maintainer directly. We will respond as
quickly as we can. This is a small open-source project maintained on
a best-effort basis, but we take security seriously.

## Code of conduct

Be kind. Be patient. Assume good faith. We're all here because we
care about secure communication and want Dart/Flutter to have better
cryptography tools.

Disagreements are fine. Personal attacks are not.

## License

By contributing, you agree that your contributions will be licensed
under the same [GNU AGPL-3.0](LICENSE) that covers the project.

If you need to contribute code that you are not able to license under
AGPL-3.0 (for example, because your employer requires different
terms), open an issue first to discuss before submitting a PR.

## Questions?

Open a GitHub Discussion or issue. We're happy to help.

Thank you for contributing!
