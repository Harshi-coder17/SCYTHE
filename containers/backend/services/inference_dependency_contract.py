"""Assert the isolated inference environment imports its declared exact pins."""
from __future__ import annotations

import importlib
from importlib import metadata
import json
from pathlib import Path
import re

MODULES = {"torch": "torch", "torchvision": "torchvision", "numpy": "numpy",
           "scikit-learn": "sklearn", "joblib": "joblib", "pillow": "PIL", "timm": "timm",
           "open-clip-torch": "open_clip", "huggingface-hub": "huggingface_hub", "lightgbm": "lightgbm"}


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def verify(requirements, *, distributions=None, importer=importlib.import_module):
    expected = {}
    for line in Path(requirements).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "--")):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)", line)
        if not match:
            raise RuntimeError("inference_dependency_contract_requires_exact_pins")
        name, version = canonical(match[1]), match[2]
        if name in expected or name not in MODULES:
            raise RuntimeError("duplicate_or_unknown_inference_dependency_pin")
        expected[name] = version
    found = {}
    for distribution in metadata.distributions() if distributions is None else distributions:
        name = canonical(distribution.metadata["Name"])
        if name in expected:
            found.setdefault(name, []).append(distribution.version)
    actual = {}
    for name, version in expected.items():
        if found.get(name) != [version]:
            raise RuntimeError("inference_dependency_metadata_missing_mismatched_or_duplicated:" + name)
        module = importer(MODULES[name])
        imported = getattr(module, "__version__", None)
        if imported is not None and str(imported) != version:
            raise RuntimeError("inference_imported_dependency_version_mismatch:" + name)
        actual[name] = {"declared": version, "metadata": found[name][0], "imported": str(imported) if imported is not None else None}
    return {"status": "verified", "dependencies": actual}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parents[1] / "requirements.shadow.txt")))
