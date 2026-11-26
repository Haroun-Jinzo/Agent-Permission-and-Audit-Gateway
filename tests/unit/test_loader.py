from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest
import yaml

from gateway.infra.loader import (
    ConfigError,
    ManifestError,
    PolicyError,
    load_config,
    load_manifests,
    load_policy,
)
from gateway.policy_eval import validate

POLICY_YAML = """
schema_version: 1
name: test-policy
lists:
  internal_domains:
    - company.example
rules:
  - rule_id: INTERNAL-EMAIL
    effect: allow
    applies_to:
      roles: [support]
      tools: [send_email]
    when:
      all:
        - arg: to
          op: domain_in
          list: internal_domains
          quantifier: all
"""

MANIFEST_YAML = """
---
schema_version: 1
tool: send_email
version: 1
risk: high
external_sink: true
argument_schema:
  type: object
  properties:
    to:
      type: array
      items:
        type: string
  required: [to]
  additionalProperties: false
sensitive_fields: [body]
derived_facts: []
default_output_labels: []
"""

INVALID_POLICY_MUTATIONS = [
    lambda policy: policy["rules"].append(dict(policy["rules"][0])),
    lambda policy: policy["rules"][0]["when"]["all"][0].update(arg="typo"),
    lambda policy: policy["rules"][0]["when"]["all"][0].pop("quantifier"),
    lambda policy: policy["rules"][0]["when"]["all"][0].update(
        list="missing-list"
    ),
    lambda policy: (
        policy["rules"][0]["applies_to"].update(tools=["*"]),
    ),
    lambda policy: policy["rules"][0].update(effect="permit"),
]


def write_yaml(path: Path, value: dict) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")


def write_example_files(tmp_path: Path) -> tuple[Path, Path]:
    policy_path = tmp_path / "policy.yaml"
    manifest_path = tmp_path / "manifests.yaml"

    policy_path.write_text(POLICY_YAML, encoding="utf-8")
    manifest_path.write_text(MANIFEST_YAML, encoding="utf-8")

    return policy_path, manifest_path


def test_load_policy_records_hash_and_version(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    raw = POLICY_YAML.encode("utf-8")
    policy_path.write_bytes(raw)

    loaded = load_policy(policy_path)

    expected_hash = hashlib.sha256(raw).hexdigest()

    assert loaded.document["name"] == "test-policy"
    assert loaded.name == "test-policy"
    assert loaded.version == 1
    assert loaded.content_hash == expected_hash
    assert loaded.policy_version == f"test-policy@1:{expected_hash[:12]}"


def test_load_manifest_records_fields(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests.yaml"
    manifest_path.write_text(MANIFEST_YAML, encoding="utf-8")

    manifests = load_manifests(manifest_path)

    assert set(manifests) == {"send_email"}

    manifest = manifests["send_email"]

    assert manifest.tool == "send_email"
    assert manifest.version == 1
    assert len(manifest.content_hash) == 64
    assert manifest.document["risk"] == "high"
    assert manifest.document["external_sink"] is True


def test_load_config_loads_example_documents(tmp_path: Path) -> None:
    policy_path, manifest_path = write_example_files(tmp_path)

    config = load_config(policy_path, manifest_path)

    assert config.policy.name == "test-policy"
    assert set(config.manifests) == {"send_email"}

    validate(config.policy.document, {
        tool: manifest.document
        for tool, manifest in config.manifests.items()
    })


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    manifest_path = tmp_path / "manifests.yaml"

    policy_path.write_text(
        """
        schema_version: 1
        name: duplicate
        name: duplicated-again
        rules: []
        """,
        encoding="utf-8",
    )
    manifest_path.write_text(MANIFEST_YAML, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(policy_path, manifest_path)


def test_duplicate_manifest_tool_is_rejected(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests.yaml"
    manifest_path.write_text(
        MANIFEST_YAML + "\n" + MANIFEST_YAML,
        encoding="utf-8",
    )

    with pytest.raises(ManifestError):
        load_manifests(manifest_path)


def test_invalid_manifest_risk_is_rejected(tmp_path: Path) -> None:
    document = yaml.safe_load(MANIFEST_YAML)
    document["risk"] = "severe"

    manifest_path = tmp_path / "manifests.yaml"
    write_yaml(manifest_path, document)

    with pytest.raises(ManifestError):
        load_manifests(manifest_path)


def test_invalid_manifest_label_is_rejected(tmp_path: Path) -> None:
    document = yaml.safe_load(MANIFEST_YAML)
    document["default_output_labels"] = ["TOP_SECRET"]

    manifest_path = tmp_path / "manifests.yaml"
    write_yaml(manifest_path, document)

    with pytest.raises(ManifestError):
        load_manifests(manifest_path)


@pytest.mark.parametrize("mutate", INVALID_POLICY_MUTATIONS)
def test_invalid_policy_mutations_are_rejected(
    tmp_path: Path,
    mutate,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    manifest_path = tmp_path / "manifests.yaml"

    manifest_path.write_text(MANIFEST_YAML, encoding="utf-8")

    policy = yaml.safe_load(POLICY_YAML)
    policy = copy.deepcopy(policy)
    mutate(policy)
    write_yaml(policy_path, policy)

    with pytest.raises((PolicyError, ConfigError)):
        load_config(policy_path, manifest_path)


def test_missing_manifest_file_is_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(policy_path, tmp_path / "missing.yaml")


def test_missing_policy_file_is_rejected(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests.yaml"
    manifest_path.write_text(MANIFEST_YAML, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml", manifest_path)


def test_malformed_utf8_is_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_bytes(b"\xff\xfe\xfa")

    with pytest.raises(PolicyError):
        load_policy(policy_path)
