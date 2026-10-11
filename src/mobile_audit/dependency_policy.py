"""Explicit, local-only dependency transmission exclusions."""

from dataclasses import dataclass
from fnmatch import fnmatchcase


@dataclass(frozen=True)
class DependencyTransmissionPolicy:
    """Case-sensitive shell patterns; coordinates use ``ecosystem:name``.

    This policy governs network transmission, independently of vulnerability
    applicability. An excluded package must never count as checked, even if an
    older successful query is present in the local cache.
    """

    exclude_ecosystems: tuple[str, ...] = ()
    exclude_names: tuple[str, ...] = ()
    exclude_coordinates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field in ("exclude_ecosystems", "exclude_names", "exclude_coordinates"):
            patterns = getattr(self, field)
            if not isinstance(patterns, (tuple, list)) or len(patterns) > 256:
                raise ValueError("Dependency exclusion patterns must be a bounded sequence")
            if any(
                not isinstance(pattern, str)
                or not pattern
                or len(pattern) > 512
                or any(ord(char) < 32 for char in pattern)
                for pattern in patterns
            ):
                raise ValueError("Dependency exclusion patterns must be nonempty bounded strings")
            object.__setattr__(self, field, tuple(patterns))

    def excludes(self, dep: dict) -> bool:
        ecosystem, name = dep.get("ecosystem", ""), dep.get("name", "")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            return False
        return (
            any(fnmatchcase(ecosystem, pattern) for pattern in self.exclude_ecosystems)
            or any(fnmatchcase(name, pattern) for pattern in self.exclude_names)
            or any(fnmatchcase(f"{ecosystem}:{name}", pattern) for pattern in self.exclude_coordinates)
        )
