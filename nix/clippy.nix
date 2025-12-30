{
  cargoArtifacts,
  craneLib,
  nativeArgs,
}:
craneLib.cargoClippy (
  nativeArgs
  // {
    inherit cargoArtifacts;

    cargoClippyExtraArgs = "--all-targets -- --deny warnings";
  }
)
