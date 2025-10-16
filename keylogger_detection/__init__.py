# python package initializer
# imports the main detection function so it can be accessed directly from the package

from .detect import detect_keylogger

__all__ = ["detect_keylogger"]
