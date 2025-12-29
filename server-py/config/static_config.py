from __future__ import annotations

import importlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ConfigSource:
    module: str
    attr: str


CONFIG_BY_FILENAME: dict[str, ConfigSource] = {
    "MazeConfig.json": ConfigSource("server.config.maze_config", "RESPONSE_TO_CLIENT"),
    "pvp_reward.json": ConfigSource("server.config.pvp_reward", "RESPONSE"),
    "shop_in_app_purchase.json": ConfigSource("server.config.shop_in_app_purchase", "RESPONSE"),
    "pve_season.json": ConfigSource("server.config.pve_season", "RESPONSE"),
    "dailySeasonData.json": ConfigSource("server.config.daily_season_data", "RESPONSE"),
    "activity_christmas.json": ConfigSource("server.config.activity_christmas", "RESPONSE"),
    "farm_pvp_rank_reward.json": ConfigSource("server.config.farm_pvp_rank_reward", "RESPONSE"),
    "game_choice_box.json": ConfigSource("server.config.game_choice_box", "RESPONSE"),
    "farm_pvp_season.json": ConfigSource("server.config.farm_pvp_season", "RESPONSE"),
    "MazeLine.json": ConfigSource("server.config.maze_line", "RESPONSE"),
    "pve_stage_rank_reward.json": ConfigSource("server.config.pve_stage_rank_reward", "RESPONSE"),
    "pvp_season.json": ConfigSource("server.config.pvp_season", "RESPONSE"),
    "pve_week_rank_reward.json": ConfigSource("server.config.pve_week_rank_reward", "RESPONSE"),
    "game_config.json": ConfigSource("server.config.game_config", "RESPONSE"),
    "game_activity_treasure.json": ConfigSource("server.config.game_activity_treasure", "RESPONSE"),
    "worldcup_matches.json": ConfigSource("server.config.worldcup_matches", "RESPONSE"),
    "battlePassConfigData.json": ConfigSource("server.config.battle_pass_config_data", "RESPONSE"),
}


def _normalize_json_text(text: str) -> str:
    """Return valid JSON text if possible.

    Some dumped config blobs are stored as fragments (e.g. missing outer braces).
    We try a couple of conservative normalizations so the client gets parseable JSON.
    """

    raw = text.strip()
    if not raw:
        return "{}"

    # Already a top-level array/object?
    if raw[0] in "{[":
        return raw

    # Best-effort: wrap fragments as an object.
    wrapped = "{\n" + raw + "\n}\n"
    try:
        json.loads(wrapped)
        return wrapped
    except Exception:
        # If even that fails, return raw as-is; caller can decide.
        return raw


def _load_override(filename: str, *, profile: str | None = None) -> str | None:
    override_dir = os.environ.get("ARCHERO_CONFIG_OVERRIDE_DIR")
    if not override_dir:
        return None
    base = Path(override_dir)

    candidates: list[Path] = []
    if profile:
        candidates.append(base / profile / filename)
    candidates.append(base / filename)

    for path in candidates:
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
    return None


def load_config_json(filename: str, *, profile: str | None = None) -> str | None:
    """Load config file contents as JSON text (string).

    If `ARCHERO_CONFIG_OVERRIDE_DIR` is set and contains `filename`, that file wins.
    Otherwise uses the baked-in dumps under `server/config/*.py`.
    """

    override = _load_override(filename, profile=profile)
    if override is not None:
        return _normalize_json_text(override)

    source = CONFIG_BY_FILENAME.get(filename)
    if source is None:
        return None

    mod = importlib.import_module(source.module)
    text = getattr(mod, source.attr, None)
    if not isinstance(text, str):
        return None
    return _normalize_json_text(text)
