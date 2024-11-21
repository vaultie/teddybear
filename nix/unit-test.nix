{
  cargoArtifacts,
  craneLib,
  nativeArgs,
}:
craneLib.cargoTest (nativeArgs
  // {
    inherit cargoArtifacts;
  })
