"""FileGuardian — advisor for list_files + read_file."""
from __future__ import annotations

from typing import ClassVar

from agents.guardian.specialists.base import (
    BaseSpecialist, SpecialistRequest, SpecialistReply,
)


class FileGuardian(BaseSpecialist):
    name: ClassVar[str] = "FileGuardian"
    handles_tools: ClassVar[tuple[str, ...]] = ("list_files", "read_file")
    tool_caps: ClassVar[dict[str, tuple[int, float]]] = {
        "read_file": (10, 60.0),
    }
    rate_per_sec: ClassVar[int] = 10
    behavior_cap: ClassVar[int] = 10
    behavior_window_s: ClassVar[float] = 10.0

    RESTRICTED_PREFIXES: ClassVar[tuple[str, ...]] = (
        "/restricted/", "/private/", "/secret/", "/.env",
    )

    def analyze(self, req: SpecialistRequest) -> SpecialistReply:
        args = req.args or {}
        if req.tool == "list_files":
            path = str(args.get("path", "") or "")
            if any(path.startswith(p) for p in self.RESTRICTED_PREFIXES):
                return self._reply(
                    "block", f"listing restricted path {path}",
                )
            return self._reply("allow", "list under non-restricted path")

        # read_file
        path = str(args.get("path", "") or "")
        if any(path.startswith(p) for p in self.RESTRICTED_PREFIXES):
            # Reads of restricted paths are only allowed from trusted sources
            if req.source_trust != "trusted":
                return self._reply(
                    "block",
                    f"restricted read {path} from {req.source_trust} source",
                )
        return self._reply("allow", f"read {path} within policy")
