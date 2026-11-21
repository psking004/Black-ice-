from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from blackice.crypto import EnvelopeSigner, canonical_json
from blackice.models import ActionRequest, ArtifactInspectRequest


def test_envelope_signature_is_stable_and_detects_payload_changes():
    signer = EnvelopeSigner(b"t" * 32)
    payload = {"agent_id": "agent", "capabilities": ["filesystem.read"]}
    signature = signer.sign(payload)
    assert signer.verify(payload, signature)
    assert not signer.verify({**payload, "agent_id": "attacker"}, signature)
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_action_rejects_nonfinite_data_and_oversized_content():
    with pytest.raises(ValidationError):
        ActionRequest(
            task_id="task-12345678",
            agent_id="agent",
            tool_id="filesystem",
            operation="write",
            resource="file.txt",
            requested_capability="filesystem.write",
            parameters={"number": math.nan},
        )


def test_artifact_provenance_is_bounded_and_filename_is_a_basename():
    with pytest.raises(ValidationError):
        ArtifactInspectRequest(filename="../bad.txt", content_base64="YWJj", provenance={})
    with pytest.raises(ValidationError):
        ArtifactInspectRequest(
            filename="good.txt",
            content_base64="YWJj",
            provenance={"note": "x" * 5000},
        )
