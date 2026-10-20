# Icon Tools releases

This public repository contains signed Windows release artifacts for
Icon Tools. The application source remains in a separate private repository.

Installed clients verify every update against an Ed25519 public key embedded
in the application and then verify the executable's signed SHA-256 digest and
byte length before replacing the running version.
