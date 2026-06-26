"""KKBOX module for Haberlea."""

try:
    from .interface import ModuleInterface, module_information

    __all__ = ["ModuleInterface", "module_information"]
except ModuleNotFoundError as exc:
    # The 'haberlea' host package is absent in the standalone uvx environment
    # used by the remote-login entry point (haberlea_kkbox.remote_login). Module
    # discovery isn't needed there, so swallow only that specific case.
    if (exc.name or "").split(".")[0] != "haberlea":
        raise
    __all__ = []
