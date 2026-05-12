from pathlib import Path


RELEASE_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"


def test_release_image_publish_builds_multi_arch_manifest() -> None:
    workflow = RELEASE_WORKFLOW.read_text()

    assert "docker/setup-qemu-action" in workflow
    assert "platforms: linux/amd64,linux/arm64" in workflow
