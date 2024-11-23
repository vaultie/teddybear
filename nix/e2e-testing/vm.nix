{
  certificate,
  identity-context,
  mdoc-certificate,
  placeholder-image,
  placeholder-pdf,
  runner,
  testers,
  thumbnail-image,
}:
testers.runNixOSTest ({lib, ...}: {
  name = "teddybear-nixos-test";

  nodes.machine = {
    lib,
    modulesPath,
    pkgs,
    ...
  }: {
    imports = [
      (modulesPath + "/profiles/minimal.nix")
      (modulesPath + "/profiles/perlless.nix")
    ];

    # Minimize the VM size
    system = {
      etc.overlay.mutable = false;
      forbiddenDependenciesRegexes = lib.mkForce [];
    };
    networking = {
      firewall.enable = false;
      resolvconf.enable = false;
    };
    users.mutableUsers = false;
    fonts.fontconfig.enable = false;
    boot.initrd.includeDefaultModules = false;
    systemd.enableEmergencyMode = false;

    systemd.services = {
      generate-cert = {
        before = ["static-web-server.service"];
        requiredBy = ["static-web-server.service"];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = pkgs.writeShellScript "generate-cert" ''
            # Self-signed testing certificates are required to correctly setup
            # DoH CoreDNS and SWE functionality
            ${lib.getExe pkgs.openssl} req -x509 \
              -newkey rsa:4096 \
              -days 3 \
              -sha256 \
              -out /var/lib/ssl/cert.pem \
              -keyout /var/lib/ssl/key.pem \
              -nodes \
              -subj "/CN=localhost"

            # CoreDNS has DynamicUser activated in the systemd service configuration,
            # so we have to make keys world-readable instead of changing owner to a specific user.
            chmod 444 /var/lib/ssl/*
          '';
          StateDirectory = "ssl";
        };
      };
    };

    services.static-web-server = {
      enable = true;
      root = "/etc/did-web-root";
      listen = "127.0.0.1:443";
      configuration.general = {
        http2 = true;
        http2-tls-cert = "/var/lib/ssl/cert.pem";
        http2-tls-key = "/var/lib/ssl/key.pem";
      };
    };

    environment = {
      etc.did-web-root.source = ./web-root;

      variables = {
        CERTIFICATE = certificate;
        IDENTITY_CONTEXT = identity-context;
        MDOC_CERTIFICATE = mdoc-certificate;
        PLACEHOLDER_IMAGE = placeholder-image;
        PLACEHOLDER_PDF = placeholder-pdf;
        THUMBNAIL_IMAGE = thumbnail-image;

        # We use self-signed certificates for testing purposes.
        NODE_TLS_REJECT_UNAUTHORIZED = "0";
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("static-web-server.service")
    machine.succeed("${lib.getExe runner}")
  '';
})
