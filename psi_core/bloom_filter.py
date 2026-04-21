"""
psi_core/bloom_filter.py
Probabilistic Bloom Filter for PSI-Lite single-account lookups (Bank B).
Uses bitarray + mmh3 (MurmurHash3) for space-efficient membership testing.
"""

import math
import mmh3
from bitarray import bitarray


class BloomFilter:
    """
    Space-efficient probabilistic data structure for set membership queries.
    - O(1) insertion and lookup
    - Configurable false positive rate (no false negatives)
    - Used by Bank B for sub-100ms single-identifier PSI-Lite checks
    """

    def __init__(self, capacity: int = 100_000, error_rate: float = 0.001):
        """
        Initialize Bloom Filter.
        capacity   — expected maximum number of elements
        error_rate — acceptable false positive probability (e.g., 0.001 = 0.1%)
        """
        self.capacity = capacity
        self.error_rate = error_rate
        # Optimal bit array size: m = -n*ln(p) / (ln2)^2
        self.size = self._optimal_size(capacity, error_rate)
        # Optimal number of hash functions: k = (m/n) * ln2
        self.hash_count = self._optimal_hash_count(self.size, capacity)
        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)
        self._count = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m) + 1

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        k = (m / n) * math.log(2)
        return max(1, int(k))

    def _get_hash_positions(self, item: str) -> list:
        """Returns `hash_count` bit positions for the given item."""
        positions = []
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i, signed=False)
            positions.append(digest % self.size)
        return positions

    def add(self, item: str):
        """Insert an item into the Bloom Filter."""
        for pos in self._get_hash_positions(item):
            self.bit_array[pos] = 1
        self._count += 1

    def __contains__(self, item: str) -> bool:
        """
        Check membership. Returns True if item is possibly in the set,
        False if definitely not in the set.
        """
        return all(self.bit_array[pos] for pos in self._get_hash_positions(item))

    def __len__(self) -> int:
        return self._count

    def rebuild(self, items: list):
        """Wipe and rebuild the filter from a fresh list of items."""
        self.bit_array.setall(0)
        self._count = 0
        for item in items:
            self.add(item)
