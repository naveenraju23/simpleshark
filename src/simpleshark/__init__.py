import sys


class UnsupportedVersionException(Exception):
    pass


if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 5):
    raise UnsupportedVersionException("Your version of Python is unsupported. "
                                      "Simpleshark requires Python >= 3.5 & Wireshark >= 2.2.0. ")

from simpleshark.capture.capture import FileCapture
