"""Exceptions raised by the reconnaissance layer.

The route handlers translate these into friendly JSON messages so that users
never see a Python traceback.
"""


class ReconError(Exception):
    """Base class for reconnaissance failures."""


class NetworkDetectionError(ReconError):
    """The local network could not be reliably determined.

    Raised instead of guessing. The user can set ``RECON_SUBNET`` to specify the
    target subnet explicitly.
    """


class TargetNotAllowed(ReconError):
    """The requested target network is outside the permitted scope.

    Discovery is restricted to small subnets wholly contained within the RFC1918
    private ranges.
    """
