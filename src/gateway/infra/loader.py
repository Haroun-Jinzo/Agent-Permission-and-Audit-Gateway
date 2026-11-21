from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError

from gateway.policy_eval import (
    PolicyError as ReferencePolicyError,
    validate as validate_policy,
)

_LABELS = frozenset({"PUBLIC", "CONFIDENTIAL", "SECRET", "UNTRUSTED"})
_RISKS = frozenset({"low", "medium", "high", "critical"})


class LoaderError(ValueError):
    """Raised when configuration loading fails."""


class ConfigError(LoaderError):
    """Raised when the complete configuration is invalid."""


class PolicyError(LoaderError):
    """Raised when a policy document is invalid."""


class ManifestError(LoaderError):
    """Raised when a manifest document is invalid."""


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    document: dict[str, Any]
    name: str
    version: int
    content_hash: str
    policy_version: str


@dataclass(frozen=True, slots=True)
class LoadedManifest:
    document: dict[str, Any]
    tool: str
    version: int
    content_hash: str


@dataclass(frozen=True, slots=True)
class Config:
    policy: LoadedPolicy
    manifests: dict[str, LoadedManifest]


class _UniqueKeyLoader(yaml.SafeLoader):
    pass

def _construct_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)

        try:
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate key: {key}",
                    key_node.start_mark,
                )
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be hashable",
                key_node.start_mark,
            ) from exc

        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping

_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _read_bytes(path: str | Path) -> tuple[Path, bytes]:
    resolved = Path(path)

    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise LoaderError(f"failed to read {resolved}: {exc}") from exc
    
    return resolved, raw

def _parse_yaml(raw: bytes, source: Path) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LoaderError(f"{source} is not valid UTF-8:") from exc
    
    try:
        return yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise LoaderError(f"invalid YAML in {source}: {exc}") from exc

def _parse_yaml_all(raw: bytes, source: Path) -> list[Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LoaderError(f"{source} is not valid UTF-8") from exc
    
    try:
        return list(yaml.load_all(text, Loader=_UniqueKeyLoader))
    except yaml.YAMLError as exc:
        raise LoaderError(f"invalid YAML in {source}: {exc}") from exc

def _validate_manifest(document: dict[str, Any], source: Path) -> None:
    if document.get("schema_version") != 1:
        raise ManifestError(f"{source}: unsupported schema_version ")
    
    tool = document.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise ManifestError(f"{source}: tool must be a non-empty string")
    
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ManifestError(f"{source}: version must be a positive integer")
    
    argument_schema = document.get("argument_schema")
    if not isinstance(argument_schema, dict):
        raise ManifestError(f"{source}: argument_schema must be a mapping")

    risk = document.get("risk", "critical")
    if risk not in _RISKS:
        raise ManifestError(f"{source}: invalid risk {risk!r}")
    
    if not isinstance(document.get("external_sink", False), bool):
        raise ManifestError(f"{source}: external_sink must be a boolean")

    for field_name in ("sensitive_fields", "derived_facts"):
        values = document.get(field_name, [])
        if not isinstance(values, list):
            raise ManifestError(f"{source}: {field_name} must be a list")
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ManifestError(f"{source}: {field_name} must contain non empty strings")

        
    labels = document.get("default_output_labels", [])
    if not isinstance(labels, list):
        raise ManifestError(f"{source}: default_output_labels must be a list")
    
    if not set(labels) <= _LABELS:
        raise ManifestError(f"{source}: default_output_labels must be a subset of {_LABELS}")


def load_manifests(path: str | Path) -> dict[str, LoadedManifest]:
    try:
        resolved, raw = _read_bytes(path)
    except LoaderError as exc:
        raise ManifestError(str(exc)) from exc

    try:
        documents = _parse_yaml_all(raw, resolved)
    except LoaderError as exc:
        raise ManifestError(f"{resolved}: {exc}") from exc
    
    manifests: dict[str, LoadedManifest] = {}

    if not documents:
        raise ManifestError(f"{resolved}: no documents found")

    for document in documents:
        if document is None:
            continue
        if not isinstance(document, dict):
            raise ManifestError(f"{resolved}: each document must be a mapping")
        
        source = f"{resolved}"
        _validate_manifest(document, resolved)

        tool = document["tool"]

        if tool in manifests:
            raise ManifestError(f"{resolved}: duplicate manifest for tool {tool!r}")
        
        file_hash = hashlib.sha256(raw).hexdigest()
        manifests[tool] = LoadedManifest(document=document, tool=tool, version=document["version"], content_hash=file_hash)
    
    if not manifests:
        raise ManifestError(f"{resolved}: no manifest documents found")
    
    return manifests

def load_policy(path: str | Path) -> LoadedPolicy:
    try:
        resolved, raw = _read_bytes(path)
    except LoaderError as exc:
        raise PolicyError(str(exc)) from exc

    try:
        document = _parse_yaml(raw, resolved)
    except LoaderError as exc:
        raise PolicyError(str(exc)) from exc

    if not isinstance(document, dict):
        raise PolicyError(f"{resolved}: policy must be mapping")
    
    if document.get("schema_version") != 1:
        raise PolicyError(f"{resolved}: name must a non-empty string")
    
    name = document.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyError(f"{resolved}: name must be a non-empty string")

    rules = document.get("rules")
    if not isinstance(rules, list):
        raise PolicyError(f"{resolved}: rules must be a list")
    
    content_hash = hashlib.sha256(raw).hexdigest()
    policy_version = f"{name}@1:{content_hash[:12]}"

    return LoadedPolicy(
        document=document,
        name=name,
        version=1,
        content_hash=content_hash,
        policy_version=policy_version,
    )

def load_config(policy_path: str | Path, manifest_path: str | Path) -> Config:
    try:
        loaded_manifests = load_manifests(manifest_path)
    except ManifestError as exc:
        raise ConfigError(f"failed to load manifests: {exc}") from exc
    
    manifests_documents = {tool: manifest.document for tool, manifest in loaded_manifests.items()}

    try:
        loaded_policy = load_policy(policy_path)
    except PolicyError as exc:
        raise ConfigError(f"invalid policy: {exc}") from exc

    try:
        validate_policy(loaded_policy.document, manifests_documents,)

    except ReferencePolicyError as exc:
        raise ConfigError(f"invalid policy: {exc}") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"malformed policy: {exc}") from exc
    
    return Config(policy=loaded_policy, manifests=loaded_manifests,)