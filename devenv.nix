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
  ];

  # https://devenv.sh/languages/
  languages = {
    go.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
