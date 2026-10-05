"""Validated process configuration. Environment variables are read at startup."""

from dataclasses import dataclass
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    db_path: Path = ROOT / "data" / "prahari.db"
    model_directory: Path = ROOT / "models"
    policy: str = "review-first"
    review_threshold: float = 30
    integration_key: str = ""

    def __post_init__(self):
        if self.policy not in ("review-first", "demo-strict"):
            raise ValueError("PRAHARI_POLICY must be review-first or demo-strict")
        if not 1 <= self.review_threshold <= 90:
            raise ValueError("PRAHARI_REVIEW_THRESHOLD must be between 1 and 90")

    @classmethod
    def from_env(cls):
        return cls(
            db_path=Path(os.getenv("PRAHARI_DB", str(ROOT / "data" / "prahari.db"))),
            model_directory=Path(os.getenv("PRAHARI_MODELS_DIR", str(ROOT / "models"))),
            policy=os.getenv("PRAHARI_POLICY", "review-first"),
            review_threshold=float(os.getenv("PRAHARI_REVIEW_THRESHOLD", "30")),
            integration_key=os.getenv("PRAHARI_INTEGRATION_KEY", ""),
        )
