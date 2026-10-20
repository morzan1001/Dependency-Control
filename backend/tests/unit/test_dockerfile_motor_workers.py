import re
from pathlib import Path

from app.db.mongodb import DEFAULT_MAX_POOL_SIZE

_DOCKERFILE = Path(__file__).parents[2] / "Dockerfile"


def test_the_image_gives_motor_one_executor_thread_per_pooled_connection():
    env = dict(re.findall(r"^ENV (\w+)=(\S+)$", _DOCKERFILE.read_text(), re.MULTILINE))

    assert env.get("MOTOR_MAX_WORKERS") == str(DEFAULT_MAX_POOL_SIZE)
