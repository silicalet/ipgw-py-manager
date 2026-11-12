{ pkgs ? import <nixpkgs> {} }:

pkgs.python3Packages.buildPythonPackage rec {
  pname = "NEU-ipgw-manager";
  version = "3.3"; # 与 ipgw/__init__.py 保持一致

  src = ./.;

  pyproject = true;

  propagatedBuildInputs = with pkgs.python3Packages; [
    requests
    click
    beautifulsoup4
    tabulate
    wcwidth
    platformdirs
    setuptools
    setupmeta
  ];

  meta = with pkgs.lib; {
    description = "ipgw maanger for NEU network gateway";
    homepage = "https://pypi.org/project/NEU-ipgw-manager/";
    license = licenses.mit;
    maintainers = [ ]; 
  };
}
