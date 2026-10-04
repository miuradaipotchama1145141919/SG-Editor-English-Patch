from __future__ import annotations


class TranslationError(RuntimeError):
    pass


class CliError(Exception):
    def __init__(self, message: str, exitCode: int = 2):
        super().__init__(message)
        self.exitCode = exitCode
