{
  description = "Entorno de desarrollo para proyecto Python con Ruff y otras herramientas";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          # Herramientas que estarán disponibles en el shell del proyecto
          buildInputs = [
            pkgs.ruff           # Linter y formateador rápido de Python
            pkgs.python3      # Intérprete de Python (puedes cambiar la versión)
          ];

          # Comando opcional que se ejecuta al entrar al entorno
          shellHook = ''
            echo "Environment activated"
            echo "Tool versions: $(ruff --version)"
          '';
        };
      });
}

