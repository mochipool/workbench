"""Registry of the workflows the CLI offers."""

from ..engine import Workflow
from .kes_rotate import KesRotate
from .transactions import ClaimRewards, PoolUpdate, SendAda

REGISTRY: dict[str, Workflow] = {w.name: w for w in (KesRotate(), ClaimRewards(), SendAda(), PoolUpdate())}
