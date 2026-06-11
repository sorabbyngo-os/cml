"""Static guard: cml_client default NATS_URL must match sorabbyngo.conf port."""
import importlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nats_url_matches_sorabbyngo_conf_default():
    saved = os.environ.pop("NATS_URL", None)
    try:
        import cml_client
        importlib.reload(cml_client)
        default_url = cml_client.NATS_URL
    finally:
        if saved is not None:
            os.environ["NATS_URL"] = saved

    conf_path = ROOT.parent / "sorabbyngo-os" / "nats" / "sorabbyngo.conf"
    if not conf_path.exists():
        import pytest
        pytest.skip(f"sorabbyngo.conf not found at {conf_path}")

    conf_text = conf_path.read_text()
    port_line = next(
        (l for l in conf_text.splitlines() if l.strip().startswith("port:")),
        None,
    )
    assert port_line is not None
    conf_port = port_line.split(":", 1)[1].strip()
    assert conf_port in default_url, (
        f"cml_client NATS_URL ({default_url}) doesn't match "
        f"sorabbyngo.conf port ({conf_port})"
    )
