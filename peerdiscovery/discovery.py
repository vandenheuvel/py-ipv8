import abc

from random import choice
from time import time


class DiscoveryStrategy(object):
    """
    Strategy for discovering peers in a network.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, overlay):
        self.overlay = overlay

    @abc.abstractmethod
    def take_step(self, service_id=None):
        pass


class RandomWalk(DiscoveryStrategy):
    """
    Walk randomly through the network.
    """

    NODE_TIMEOUT = 3.0

    def __init__(self, overlay):
        super(RandomWalk, self).__init__(overlay)
        self.intro_timeouts = {}

    def take_step(self, service_id=None):
        """
        Walk to random walkable peer.
        """
        # Sanitize unreachable nodes
        to_remove = []
        for node in self.intro_timeouts:
            if self.intro_timeouts[node] + self.NODE_TIMEOUT < time():
                to_remove.append(node)
        for node in to_remove:
            del self.intro_timeouts[node]
            self.overlay.network.remove_by_address(node)
        # Take step
        known = self.overlay.network.get_walkable_addresses(service_id)
        available = list(set(known) - set(self.intro_timeouts.keys()))

        if available:
            peer = choice(available)
            self.overlay.walk_to(peer)
            self.intro_timeouts[peer] = time()
        else:
            self.overlay.get_new_introduction(service_id=service_id)


class EdgeWalk(DiscoveryStrategy):
    """
    Walk through the network by using edges.

    This will perform a depth-first search in the network starting from your direct neighborhood.
    When a certain depth is reached, we teleport home and start again from our neighborhood.
    """

    EDGE_TIMEOUT = 3.0

    def __init__(self, overlay, edge_length=4, neighborhood_size=6):
        super(EdgeWalk, self).__init__(overlay)
        self._neighborhood = []

        self.complete_edges = []
        self.under_construction = {}
        self.last_edge_responses = {}

        self.edge_length = edge_length
        self.neighborhood_size = neighborhood_size

    def get_available_root(self):
        """
        Get a root, if it exists, which is not busy constructing an edge for us.
        """
        available = list(set(self._neighborhood) - set(self.under_construction.keys()))
        return choice(available) if available else None

    def take_step(self, service_id=None):
        """
        Attempt to grow an edge.
        """
        if not self._neighborhood or len(self._neighborhood) < self.neighborhood_size:
            # Wait for our immediate neighborhood to be discovered
            self._neighborhood = self.overlay.network.verified_peers[:self.neighborhood_size]
            self.overlay.get_new_introduction(service_id=service_id)
        else:
            waiting_root = self.get_available_root()
            # Make sure we have as many outstanding/actively growing edges as roots
            if waiting_root:
                self.under_construction[waiting_root] = []
                self.last_edge_responses[waiting_root] = time()
                self.overlay.get_new_introduction(waiting_root.address, service_id=service_id)
            else:
                # Check if our introduced peer has answered yet
                completed = []
                for root in self.under_construction:
                    last_verified = self.under_construction[root][-1] if self.under_construction[root] else root
                    introductions = self.overlay.network.get_introductions_from(last_verified)
                    if introductions:
                        # We got (multiple?) introductions from this peer, add it as verified
                        self.last_edge_responses[root] = time()
                        self.under_construction[root].append(root if not last_verified else last_verified)
                        if len(self.under_construction[root]) == self.edge_length:
                            # We have crawled the maximum depth, teleport home
                            self.complete_edges.append(self.under_construction[root])
                            completed.append(root)
                        else:
                            # Take this edge a step further
                            self.overlay.walk_to(choice(introductions))
                    elif self.last_edge_responses[root] + self.EDGE_TIMEOUT < time():
                        # This edge isn't growing, mark it as complete
                        if len(self.under_construction[root]) > 1:
                            self.complete_edges.append(self.under_construction[root])
                            completed.append(root)
                for root in completed:
                    del self.under_construction[root]
