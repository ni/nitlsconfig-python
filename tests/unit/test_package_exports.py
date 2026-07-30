"""Tests for the package's public import surface.

grpcio is an optional extra, so nitlsconfig/__init__.py resolves the gRPC names
lazily through a module __getattr__. These tests pin the parts of that contract
that are observable with the extra installed; the CI job
"Check install without extras" covers the missing-grpcio path, which cannot be
reproduced in an environment where grpcio is present.
"""

import pytest

import nitlsconfig


def test_version_is_exported() -> None:
    """__all__ advertises __version__, so it has to exist.

    It previously did not, which made "from nitlsconfig import *" raise.
    """
    assert nitlsconfig.__version__


def test_all_names_are_importable() -> None:
    """Every name in __all__ must resolve, including the lazy gRPC ones."""
    for name in nitlsconfig.__all__:
        assert getattr(nitlsconfig, name) is not None


def test_unknown_attribute_raises_attribute_error() -> None:
    """The lazy __getattr__ must not turn typos into ImportError."""
    with pytest.raises(AttributeError, match="has no attribute 'not_a_real_name'"):
        nitlsconfig.not_a_real_name


def test_importing_the_package_does_not_import_grpc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing nitlsconfig must not pull in grpcio.

    This is what makes the extra worth having. It fails the moment someone adds
    a module-level "import grpc" to the configuration-reading code.
    """
    monkeypatch.delitem(__import__("sys").modules, "grpc", raising=False)
    monkeypatch.delitem(__import__("sys").modules, "nitlsconfig", raising=False)
    monkeypatch.delitem(__import__("sys").modules, "nitlsconfig.cli", raising=False)
    monkeypatch.delitem(__import__("sys").modules, "nitlsconfig.grpc_channel", raising=False)

    import nitlsconfig as reimported

    assert reimported.ClientConfig is not None
    assert "grpc" not in __import__("sys").modules
