import sys

from .pysequoia import *  # noqa: F403
from .pysequoia import packet as packet

# Register the native submodule so that "from pysequoia.packet import ..." works.
# Without this, Python would look for pysequoia/packet.py which doesn't exist.
sys.modules[__name__ + ".packet"] = packet
