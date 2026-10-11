import importlib.util
import os
import shutil
from pathlib import Path

import pytest

from mobile_audit.cli import demo_target
from mobile_audit.store import Store


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "state")
    yield value
    value.close()


@pytest.fixture
def demo(tmp_path):
    return demo_target(tmp_path / "demo")


@pytest.fixture(scope="session")
def compiled_apks(tmp_path_factory):
    """Compile new public Java sources; never consume retained binary inputs."""
    sdk_value = os.environ.get("APSA_TEST_ANDROID_SDK", os.environ.get("ANDROID_HOME"))
    javac = os.environ.get("APSA_TEST_JAVAC") or shutil.which("javac")
    if not sdk_value or not javac:
        pytest.skip("Fresh compiled fixtures require APSA_TEST_ANDROID_SDK and javac")
    source = Path(__file__).parent / "fixtures/binary_analysis/build.py"
    spec = importlib.util.spec_from_file_location("synthetic_dex_builder", source)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    output = tmp_path_factory.mktemp("new-compiled-apks") / "generated"
    builder.build_fixtures(
        sdk=Path(sdk_value),
        output_dir=output,
        javac=javac,
        compile_manifest=True,
        platform=os.environ.get("APSA_TEST_ANDROID_PLATFORM", "android-36"),
        build_tools=os.environ.get("APSA_TEST_ANDROID_BUILD_TOOLS", "36.0.0"),
        environment=dict(os.environ),
    )
    return output


@pytest.fixture
def apk(compiled_apks):
    return compiled_apks / "safe.apk"
