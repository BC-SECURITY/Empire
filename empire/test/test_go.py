from pathlib import Path

from empire.server.core.go import GoCompiler


def test_go_compiler_jinja_env_path(tmp_path):
    """Test that GoCompiler correctly constructs the jinja_env loader path."""
    # Create the expected directory structure
    gopire_dir = tmp_path / "data" / "agent" / "gopire"
    gopire_dir.mkdir(parents=True)

    compiler = GoCompiler(install_path=tmp_path)

    assert compiler.install_path == tmp_path

    loader = compiler.jinja_env.loader
    assert str(gopire_dir) in loader.searchpath


def test_go_compiler_accepts_path_object():
    """Test that GoCompiler works with a Path object as install_path."""
    install = Path("/fake/install/path")
    compiler = GoCompiler(install_path=install)

    assert compiler.install_path == install
    expected_loader_path = str(install / "data/agent/gopire")
    assert expected_loader_path in compiler.jinja_env.loader.searchpath
