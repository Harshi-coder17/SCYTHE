from types import SimpleNamespace

import pytest

from services import inference_dependency_contract as contract


def distribution(name, version):
    return SimpleNamespace(metadata={"Name": name}, version=version)


def test_exact_import_and_single_distribution_required(tmp_path):
    path = tmp_path / "pins.txt"
    path.write_text("scikit-learn==1.7.2\n")
    good = distribution("scikit_learn", "1.7.2")
    def imported(_name):
        return SimpleNamespace(__version__="1.7.2")
    assert contract.verify(path, distributions=[good], importer=imported)["status"] == "verified"
    with pytest.raises(RuntimeError, match="duplicated"):
        contract.verify(path, distributions=[distribution("scikit-learn", "1.5.1"), good], importer=imported)
    with pytest.raises(RuntimeError, match="imported_dependency"):
        contract.verify(path, distributions=[good], importer=lambda _: SimpleNamespace(__version__="1.5.1"))


def test_inexact_or_duplicate_pins_rejected(tmp_path):
    path = tmp_path / "pins.txt"
    for text in ("numpy>=2\n", "numpy==2.4.6\nnumpy==2.4.6\n"):
        path.write_text(text)
        with pytest.raises(RuntimeError):
            contract.verify(path, distributions=[])
