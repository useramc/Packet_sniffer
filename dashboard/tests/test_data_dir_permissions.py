import os
import stat

import pytest
from integration import _restrict_dir


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes only")
def test_restrict_dir_is_owner_only(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    d.chmod(0o777)
    _restrict_dir(d)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_restrict_dir_never_raises(tmp_path):
    _restrict_dir(tmp_path / "does-not-exist")