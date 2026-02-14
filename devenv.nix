{
  pkgs,
  lib,
  config,
  ...
}:
{
  # https://devenv.sh/packages/
  packages = [
    pkgs.caddy
    pkgs.xcaddy
    pkgs.wl-clipboard
  ];

  # https://devenv.sh/languages/
  languages = {
    go.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
  # Build the custom caddy with your local module
  processes.foundry-proxy.exec = ''
    xcaddy run 
  '';

  # Environment variables to keep things local

  # Helper to generate a dummy user map if it doesn't exist
  scripts.gen-test-data.exec = ''
    if [ ! -f user_map.json ]; then
      cp test/user.json user.json
      echo "Copied user_map.json"
    fi
    if [ ! -f Caddyfile ]; then
      cp test/user.json user.json
      echo "Copied Caddyfile"
    fi

  '';
  enterShell = ''
    gen-test-data
    echo "--- Foundry Auth Module Dev Environment ---"
    echo "Run 'devenv up' to start the proxy on port 8080"
  '';
}
