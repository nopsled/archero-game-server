from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PlayerProfile:
    player_id: int
    player_name: str
    coins: int
    gems: int
    level: int
    chapter: int
    exp: int
    talent: int

    # Placeholder for future protocol fields once we discover them.
    character_id: int | None = None


DEFAULT_PROFILE = PlayerProfile(
    player_id=170722380,
    player_name="Player 170722380",
    coins=199,
    gems=120,
    level=1,
    chapter=1,
    exp=100,
    talent=0,
    character_id=None,
)


def _parse_profile(raw: dict[str, Any]) -> PlayerProfile:
    return PlayerProfile(
        player_id=int(raw.get("player_id", DEFAULT_PROFILE.player_id)),
        player_name=str(raw.get("player_name", DEFAULT_PROFILE.player_name)),
        coins=int(raw.get("coins", DEFAULT_PROFILE.coins)),
        gems=int(raw.get("gems", DEFAULT_PROFILE.gems)),
        level=int(raw.get("level", DEFAULT_PROFILE.level)),
        chapter=int(raw.get("chapter", DEFAULT_PROFILE.chapter)),
        exp=int(raw.get("exp", DEFAULT_PROFILE.exp)),
        talent=int(raw.get("talent", DEFAULT_PROFILE.talent)),
        character_id=(
            int(raw["character_id"]) if "character_id" in raw and raw["character_id"] is not None else None
        ),
    )


def load_player_profile() -> PlayerProfile:
    """Load player profile config for the sandbox game protocol login response.

    Priority:
      1) `ARCHERO_PLAYER_PROFILE_PATH` (JSON file)
      2) `ARCHERO_PLAYER_PROFILE_JSON` (inline JSON)
      3) defaults
    """

    path = os.environ.get("ARCHERO_PLAYER_PROFILE_PATH")
    if path:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return _parse_profile(data)
        except Exception as e:
            print(f"[Config] Failed to load player profile from {path}: {e}")

    inline = os.environ.get("ARCHERO_PLAYER_PROFILE_JSON")
    if inline:
        try:
            data = json.loads(inline)
            if isinstance(data, dict):
                return _parse_profile(data)
        except Exception as e:
            print(f"[Config] Failed to parse ARCHERO_PLAYER_PROFILE_JSON: {e}")

    return DEFAULT_PROFILE

