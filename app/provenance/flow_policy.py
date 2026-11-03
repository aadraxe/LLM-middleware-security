"""Independent information-flow decision; ordinary tool ALLOW is insufficient."""
from types import MappingProxyType

from .models import Sensitivity


class FlowPolicy:
    def __init__(self, destinations, *, version="flow-v1"):
        # Exact (tenant, normalized mailbox) -> permitted sensitivities.
        # UNKNOWN is never implicitly safe, even in trusted configuration.
        self.version = version
        self._destinations = MappingProxyType({key: frozenset(Sensitivity(s) for s in values)
                                              for key, values in destinations.items()})

    def permits(self, request, exposure):
        return (exposure.sensitivity != Sensitivity.UNKNOWN and
                exposure.sensitivity in self._destinations.get(
                    (request.principal.tenant_id, request.destination), frozenset()))
