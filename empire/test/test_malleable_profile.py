"""Tests for the runtime JSON profile serializer consumed by C#/Go agents.

The Python server already builds the PowerShell/Python stager inline from
`Container.generate_*` helpers. C# and Go agents instead parse a versioned
JSON blob at runtime, so the server needs a single canonical serializer —
``Profile.serialize_for_agent`` — that walks the profile tree and emits
that blob.

These tests pin the v1 schema so the agents (which live in separate
repos) have a stable contract. Every transform op and
terminator type listed in ``transformation.py`` is round-tripped through
the serializer here; adding a new op will fail these tests until it is
mapped explicitly.
"""

import base64
import json
import re
from pathlib import Path

import pytest

from empire.server.common.malleable.profile import (
    _AGENT_PROFILE_SCHEMA_VERSION,
    HttpConfig,
    HttpsCertificate,
    Profile,
    _coerce_bool,
)
from empire.server.common.malleable.transformation import (
    Transform,
)


def _b64(value: bytes | str) -> str:
    """Helper: base64-encode append/prepend values the way the serializer does."""
    if isinstance(value, str):
        value = value.encode("latin-1")
    return base64.b64encode(value).decode("ascii")


# Directory with real-world .profile fixtures shipped with Empire. Used to
# smoke-test the serializer against non-trivial profiles.
PROFILES_DIR = Path(__file__).resolve().parent.parent / "server" / "data" / "profiles"


def _make_profile():
    """Construct a Profile with sane, explicit defaults for serializer tests.

    We set distinct uris/terminators/headers for each section so assertions
    can easily verify the output routed things into the right slot.
    """
    p = Profile()
    p.sleeptime = 12345
    p.jitter = 17

    # stager
    p.stager.client.uris = ["/stage.php"]
    p.stager.client.headers = {"User-Agent": "StagerAgent", "Accept": "text/html"}
    p.stager.client.metadata.base64()
    p.stager.client.metadata.header("Cookie")
    p.stager.server.headers = {"Server": "Apache/Stage"}
    p.stager.server.output.base64()
    p.stager.server.output.print_()

    # get
    p.get.client.uris = ["/news.php"]
    p.get.client.headers = {"User-Agent": "GetAgent"}
    p.get.client.metadata.base64()
    p.get.client.metadata.prepend("session=")
    p.get.client.metadata.header("Cookie")
    p.get.server.headers = {"Server": "Apache/Get"}
    p.get.server.output.base64()
    p.get.server.output.print_()

    # post
    p.post.client.uris = ["/submit.php"]
    p.post.client.headers = {"User-Agent": "PostAgent"}
    p.post.client.id.netbios()
    p.post.client.id.parameter("id")
    p.post.client.output.base64()
    p.post.client.output.print_()
    p.post.server.headers = {"Server": "Apache/Post"}
    p.post.server.output.base64()
    p.post.server.output.print_()

    return p


class TestSerializeForAgentTopLevel:
    def test_returns_string(self):
        p = Profile()
        blob = p.serialize_for_agent()
        assert isinstance(blob, str)
        # Should be parseable as JSON.
        json.loads(blob)

    def test_is_compact(self):
        p = Profile()
        blob = p.serialize_for_agent()
        # The serializer inlines into stager templates, so it MUST be compact
        # (no spaces after separators).
        assert ", " not in blob
        assert ": " not in blob

    def test_version_field(self):
        p = Profile()
        data = json.loads(p.serialize_for_agent())
        # The emitted "v" must equal the module-level constant; bumping
        # _AGENT_PROFILE_SCHEMA_VERSION is the intentional way to break
        # downstream agents that need to opt in to a new schema.
        assert data["v"] == _AGENT_PROFILE_SCHEMA_VERSION

    def test_gopire_supported_version_matches(self):
        # Cross-language contract pin: Gopire's supportedProfileVersion in
        # empire/server/data/agent/gopire/comms/malleable.go must agree with
        # the Python constant. If they drift, a v2 server will emit blobs
        # that v1 Gopire silently parses with zero-valued new sections —
        # worse than a hard failure.
        gopire = (
            Path(__file__).resolve().parent.parent
            / "server"
            / "data"
            / "agent"
            / "gopire"
            / "comms"
            / "malleable.go"
        )
        match = re.search(
            r"^\s*const\s+supportedProfileVersion\s*=\s*(\d+)\s*$",
            gopire.read_text(),
            re.MULTILINE,
        )
        assert match is not None, (
            "supportedProfileVersion not found in Gopire malleable.go"
        )
        assert int(match.group(1)) == _AGENT_PROFILE_SCHEMA_VERSION

    def test_sleep_and_jitter(self):
        p = Profile()
        p.sleeptime = 45000
        p.jitter = 25
        data = json.loads(p.serialize_for_agent())
        assert data["sleep"] == 45000  # noqa: PLR2004
        assert data["jitter"] == 25  # noqa: PLR2004

    def test_sections_present(self):
        p = Profile()
        data = json.loads(p.serialize_for_agent())
        assert set(data["sections"].keys()) == {"stager", "get", "post"}

    def test_each_section_has_client_and_server(self):
        p = Profile()
        data = json.loads(p.serialize_for_agent())
        for name in ("stager", "get", "post"):
            section = data["sections"][name]
            assert "client" in section
            assert "server" in section


class TestSerializeForAgentSectionShape:
    def test_get_client_has_metadata_only(self):
        data = json.loads(_make_profile().serialize_for_agent())
        get_client = data["sections"]["get"]["client"]
        assert "metadata" in get_client
        assert "output" not in get_client

    def test_stager_client_has_metadata_only(self):
        data = json.loads(_make_profile().serialize_for_agent())
        stager_client = data["sections"]["stager"]["client"]
        assert "metadata" in stager_client
        assert "output" not in stager_client

    def test_post_client_has_both_metadata_and_output(self):
        data = json.loads(_make_profile().serialize_for_agent())
        post_client = data["sections"]["post"]["client"]
        assert "metadata" in post_client
        assert "output" in post_client

    def test_server_side_has_output(self):
        data = json.loads(_make_profile().serialize_for_agent())
        for name in ("stager", "get", "post"):
            server = data["sections"][name]["server"]
            assert "output" in server
            assert "headers" in server
            assert "body_prefix" in server

    def test_client_basic_fields(self):
        data = json.loads(_make_profile().serialize_for_agent())
        get_client = data["sections"]["get"]["client"]
        assert get_client["verb"] == "GET"
        assert get_client["uris"] == ["/news.php"]
        assert get_client["headers"]["User-Agent"] == "GetAgent"
        assert "parameters" in get_client
        assert "body" in get_client

    def test_post_verb(self):
        data = json.loads(_make_profile().serialize_for_agent())
        assert data["sections"]["post"]["client"]["verb"] == "POST"


class TestTransformOpMapping:
    def _serialize_get_metadata(self, configure):
        """Build a Profile with the given configurator applied to get.client.metadata
        and return the serialized transforms list.
        """
        p = Profile()
        configure(p.get.client.metadata)
        data = json.loads(p.serialize_for_agent())
        return data["sections"]["get"]["client"]["metadata"]["transforms"]

    def test_base64(self):
        transforms = self._serialize_get_metadata(lambda c: c.base64())
        assert transforms == [{"op": "base64"}]

    def test_base64url(self):
        transforms = self._serialize_get_metadata(lambda c: c.base64url())
        assert transforms == [{"op": "base64url"}]

    def test_netbios(self):
        transforms = self._serialize_get_metadata(lambda c: c.netbios())
        assert transforms == [{"op": "netbios"}]

    def test_netbiosu(self):
        transforms = self._serialize_get_metadata(lambda c: c.netbiosu())
        assert transforms == [{"op": "netbiosu"}]

    def test_append(self):
        transforms = self._serialize_get_metadata(lambda c: c.append("tail"))
        # append/prepend value is base64-encoded raw bytes (latin-1 source).
        assert transforms == [{"op": "append", "value": _b64("tail")}]

    def test_prepend(self):
        transforms = self._serialize_get_metadata(lambda c: c.prepend("head="))
        assert transforms == [{"op": "prepend", "value": _b64("head=")}]

    def test_prepend_high_bit_bytes_roundtrip(self):
        """A latin-1 b"\\xe9" should round-trip through base64 as 1 byte.

        Shipping it as a plain JSON string would UTF-8 encode it into 2
        bytes (0xC3 0xA9), breaking byte-exact parity with the
        PowerShell/Python server transforms.
        """
        transforms = self._serialize_get_metadata(
            lambda c: c.prepend(b"caf\xe9".decode("latin-1"))
        )
        # b"caf\xe9" -> base64 "Y2Fm6Q=="
        assert transforms == [{"op": "prepend", "value": "Y2Fm6Q=="}]
        # The decoded length matches the raw byte length (4), NOT the
        # UTF-8 length (5) that a plain JSON string would produce.
        decoded = base64.b64decode(transforms[0]["value"])
        assert decoded == b"caf\xe9"
        assert len(decoded) == len(b"caf\xe9")

    def test_mask_emits_lowercase_hex_key(self):
        transforms = self._serialize_get_metadata(
            lambda c: c.transforms.append(Transform(type=Transform.MASK, arg=b"\x42"))
        )
        assert transforms == [{"op": "mask", "key": "42"}]
        # key is 2 hex chars, lowercase
        assert transforms[0]["key"] == transforms[0]["key"].lower()
        assert len(transforms[0]["key"]) == 2  # noqa: PLR2004

    def test_none_transform_is_skipped(self):
        transforms = self._serialize_get_metadata(
            lambda c: c.transforms.append(Transform(type=Transform.NONE))
        )
        assert transforms == []

    def test_transform_ordering_preserved(self):
        transforms = self._serialize_get_metadata(
            lambda c: (c.base64(), c.prepend("hdr="), c.append(";end"))
        )
        assert transforms == [
            {"op": "base64"},
            {"op": "prepend", "value": _b64("hdr=")},
            {"op": "append", "value": _b64(";end")},
        ]


class TestTerminatorMapping:
    def _serialize_get_metadata_terminator(self, configure):
        p = Profile()
        configure(p.get.client.metadata)
        data = json.loads(p.serialize_for_agent())
        return data["sections"]["get"]["client"]["metadata"]["terminator"]

    def test_header(self):
        term = self._serialize_get_metadata_terminator(lambda c: c.header("Cookie"))
        assert term == {"type": "header", "arg": "Cookie"}

    def test_print(self):
        term = self._serialize_get_metadata_terminator(lambda c: c.print_())
        assert term == {"type": "print"}

    def test_parameter(self):
        term = self._serialize_get_metadata_terminator(lambda c: c.parameter("q"))
        assert term == {"type": "parameter", "arg": "q"}

    def test_uriappend(self):
        term = self._serialize_get_metadata_terminator(lambda c: c.uriappend())
        assert term == {"type": "uri-append"}

    def test_default_terminator_type_print(self):
        # A fresh Container() defaults to Terminator(type=PRINT). Make sure
        # we map it to {"type": "print"} rather than emitting None / unknown.
        p = Profile()
        data = json.loads(p.serialize_for_agent())
        term = data["sections"]["get"]["client"]["metadata"]["terminator"]
        assert term == {"type": "print"}


class TestPostClientRouting:
    """Post client has BOTH a routing packet container (id) and an output container."""

    def test_post_metadata_is_routing_packet(self):
        """The 'metadata' key in post.client maps to Empire's `Post.client.id`
        (the routing packet / session id container)."""
        p = Profile()
        p.post.client.id.base64()
        p.post.client.id.parameter("sess")
        p.post.client.output.netbios()
        p.post.client.output.print_()

        data = json.loads(p.serialize_for_agent())
        post_client = data["sections"]["post"]["client"]

        assert post_client["metadata"]["transforms"] == [{"op": "base64"}]
        assert post_client["metadata"]["terminator"] == {
            "type": "parameter",
            "arg": "sess",
        }
        assert post_client["output"]["transforms"] == [{"op": "netbios"}]
        assert post_client["output"]["terminator"] == {"type": "print"}


class TestRealProfile:
    """Smoke-test against a bundled real profile."""

    def _find_profile(self):
        # Profiles are vendored into the repo, so an empty tree is a packaging
        # bug, not a missing optional fixture. Fail rather than skip.
        assert PROFILES_DIR.is_dir(), f"vendored profiles missing at {PROFILES_DIR}"
        candidates = sorted(PROFILES_DIR.rglob("*.profile"))
        assert candidates, f"no .profile files under {PROFILES_DIR}"
        return candidates[0]

    def test_ingest_and_serialize_roundtrip(self):
        path = self._find_profile()

        p = Profile()
        p.ingest(file=str(path))
        blob = p.serialize_for_agent()
        data = json.loads(blob)

        # Structural sanity: required keys present.
        assert data["v"] == 1
        assert "sleep" in data
        assert "jitter" in data
        for name in ("stager", "get", "post"):
            section = data["sections"][name]
            assert isinstance(section["client"]["uris"], list)
            assert isinstance(section["client"]["headers"], dict)
            assert isinstance(section["client"]["metadata"]["transforms"], list)
            assert "type" in section["client"]["metadata"]["terminator"]
            assert isinstance(section["server"]["output"]["transforms"], list)
            assert "type" in section["server"]["output"]["terminator"]

        assert "metadata" in data["sections"]["post"]["client"]
        assert "output" in data["sections"]["post"]["client"]


class TestInvalidInput:
    def test_unknown_transform_type_is_omitted(self):
        """If someone pokes a Transform with an unrecognized type into a
        Container, the serializer should drop it rather than crash or emit
        garbage — the agent spec only defines the mapped ops."""
        p = Profile()
        rogue = Transform.__new__(Transform)
        rogue.type = 9999  # not any defined Transform constant
        rogue.arg = None
        p.get.client.metadata.transforms.append(rogue)

        # Should not raise; unknown op is silently dropped.
        data = json.loads(p.serialize_for_agent())
        assert data["sections"]["get"]["client"]["metadata"]["transforms"] == []

    def test_mask_with_invalid_arg_does_not_crash(self):
        """Mask requires a length-1 bytes arg; a malformed value should not
        blow up the whole serializer — emit best-effort or drop, but return."""
        p = Profile()
        bad = Transform.__new__(Transform)
        bad.type = Transform.MASK
        bad.arg = None  # missing key
        p.get.client.metadata.transforms.append(bad)

        # Should not raise.
        blob = p.serialize_for_agent()
        data = json.loads(blob)
        # Either dropped or emitted with empty/omitted key — but not a crash.
        masks = [
            t
            for t in data["sections"]["get"]["client"]["metadata"]["transforms"]
            if t.get("op") == "mask"
        ]
        for m in masks:
            # If present, key must still be a string (possibly empty).
            assert isinstance(m.get("key", ""), str)


class TestTier0SetDirectiveClassifier:
    """Tier 0: the top-level `set` directive parser is a three-way classifier
    (wired-up / accepted-but-ignored / unknown). Previously a single
    setattr() catch-all silently stored everything as a string, so
    `set host_stage "false";` produced a truthy attribute.
    """

    # Minimal http-get/http-post/http-stager skeleton so Profile.ingest
    # accepts the test profile body. The exact transports don't matter —
    # we're only exercising the top-level `set` parser.
    _SKELETON = """
http-get {
    set uri "/";
    client {
        metadata {
            base64;
            header "Cookie";
        }
    }
    server {
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/submit.php";
    client {
        id {
            netbios;
            parameter "id";
        }
        output {
            base64;
            print;
        }
    }
    server {
        output {
            base64;
            print;
        }
    }
}

http-stager {
    set uri_x86 "/a";
    set uri_x64 "/b";
    client {
        metadata {
            base64;
            header "Cookie";
        }
    }
    server {
        output {
            base64;
            print;
        }
    }
}
"""

    def _ingest(self, set_block: str) -> Profile:
        p = Profile()
        p.ingest(content=set_block + self._SKELETON)
        return p

    def test_default_host_stage_is_true(self):
        p = Profile()
        assert p.host_stage is True

    def test_default_sample_name_is_none(self):
        p = Profile()
        assert p.sample_name is None

    def test_host_stage_false_becomes_typed_bool(self):
        # The bug Tier 0 fixes: previously this stored the string "false"
        # which is truthy.
        p = self._ingest('set host_stage "false";\n')
        assert p.host_stage is False
        assert isinstance(p.host_stage, bool)

    def test_host_stage_true_becomes_typed_bool(self):
        p = self._ingest('set host_stage "true";\n')
        assert p.host_stage is True
        assert isinstance(p.host_stage, bool)

    def test_host_stage_garbage_value_is_falsy(self):
        # CS convention: anything not in the truthy literal set is False.
        p = self._ingest('set host_stage "definitely-not-true";\n')
        assert p.host_stage is False

    def test_sleeptime_normalized_to_int(self):
        p = self._ingest('set sleeptime "45000";\n')
        assert p.sleeptime == 45000  # noqa: PLR2004
        assert isinstance(p.sleeptime, int)

    def test_jitter_normalized_to_int(self):
        p = self._ingest('set jitter "25";\n')
        assert p.jitter == 25  # noqa: PLR2004
        assert isinstance(p.jitter, int)

    def test_sample_name_stored_verbatim(self):
        p = self._ingest('set sample_name "Operation Foo";\n')
        assert p.sample_name == "Operation Foo"

    def test_accepted_but_ignored_directive_logs_debug(self, caplog):
        # Shipped CS profiles routinely declare directives Empire does not
        # yet honor (maxdns, compile_time, image_size_*, dns_idle, userwx,
        # …). Emitting one INFO per directive per profile load — and Empire
        # loads several profiles per startup — flooded operator consoles
        # with non-actionable messages. These are diagnostics, not events.
        with caplog.at_level("DEBUG", logger="empire.server.common.malleable.profile"):
            self._ingest('set dns_idle "8.8.8.8";\n')
        debug_logs = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "DEBUG"
            and "dns_idle" in r.getMessage()
            and "does not act on it yet" in r.getMessage()
        ]
        assert debug_logs, (
            f"expected DEBUG log for accepted-but-ignored key, saw: "
            f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )

    def test_accepted_but_ignored_directive_emits_no_info_or_warning(self, caplog):
        # Stronger than the previous WARNING-only check: shipped profiles
        # produce zero INFO and zero WARNING for accepted-but-ignored keys
        # post-DEBUG-demotion. INFO would still surface in the default
        # Empire log level, defeating the purpose of the change.
        with caplog.at_level("INFO", logger="empire.server.common.malleable.profile"):
            self._ingest('set dns_idle "8.8.8.8";\n')
        loud = [
            (r.levelname, r.getMessage())
            for r in caplog.records
            if r.levelname in {"INFO", "WARNING"}
            and "does not act on it yet" in r.getMessage()
        ]
        assert loud == [], (
            f"accepted-but-ignored directives must be DEBUG-only, got: {loud}"
        )

    def test_unknown_directive_emits_warning(self, caplog):
        with caplog.at_level(
            "WARNING", logger="empire.server.common.malleable.profile"
        ):
            self._ingest('set totally_made_up_field "x";\n')
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("totally_made_up_field" in w for w in warnings), (
            f"expected WARNING mentioning the unknown key, saw: {warnings}"
        )

    def test_roundtrip_through_serialize_preserves_host_stage(self):
        p = self._ingest('set host_stage "false";\n')
        roundtripped = Profile._deserialize(p._serialize())
        assert roundtripped.host_stage is False
        assert isinstance(roundtripped.host_stage, bool)

    def test_deserialize_host_stage_string_does_not_silently_flip(self):
        # Same C2 footgun as TestTier1HttpConfigBlock's trust_xff guard, but
        # for the Tier 0 stager gate: a stored profile whose host_stage
        # round-tripped as the *string* "false" must NOT come back as True
        # via bool("false") and silently re-enable the stager URI.
        p = self._ingest('set host_stage "true";\n')
        blob = p._serialize()
        blob["host_stage"] = "false"  # simulate stringified round-trip
        roundtripped = Profile._deserialize(blob)
        assert roundtripped.host_stage is False, (
            "stringified host_stage='false' must not flip the stager gate to True"
        )
        # Sanity: a missing host_stage still defaults to the documented True.
        del blob["host_stage"]
        assert Profile._deserialize(blob).host_stage is True

    def test_roundtrip_through_clone_preserves_sample_name(self):
        p = self._ingest('set sample_name "trial-run";\n')
        assert p._clone().sample_name == "trial-run"


class TestShippedProfilesAllowList:
    """Allow-list completeness check: every shipped profile in data/profiles
    must load with zero WARNING-level logs from the malleable parser. A new
    WARNING here means either (a) a shipped profile uses a CS field we forgot
    to add to _ACCEPTED_BUT_IGNORED_SET_KEYS, or (b) a profile genuinely has
    a typo that's worth surfacing — both deserve human review.
    """

    def test_no_warnings_loading_shipped_profiles(self, caplog):
        # See _find_profile: an empty vendored tree is a bug, not a skip.
        assert PROFILES_DIR.is_dir(), f"vendored profiles missing at {PROFILES_DIR}"
        shipped = sorted(PROFILES_DIR.rglob("*.profile"))
        assert shipped, f"no .profile files under {PROFILES_DIR}"

        offenders: list[tuple[str, str]] = []
        with caplog.at_level(
            "WARNING", logger="empire.server.common.malleable.profile"
        ):
            for path in shipped:
                caplog.clear()
                p = Profile()
                try:
                    p.ingest(file=str(path))
                except Exception as exc:
                    # A profile that fails to *parse* is a different bug;
                    # the allow-list check is about runtime WARNING noise.
                    offenders.append((str(path), f"parse error: {exc}"))
                    continue
                for record in caplog.records:
                    if record.levelname == "WARNING":
                        offenders.append((str(path), record.getMessage()))

        assert offenders == [], (
            "shipped profiles produced parser warnings — either add the new key "
            "to _ACCEPTED_BUT_IGNORED_SET_KEYS in profile.py, or fix the profile:\n  "
            + "\n  ".join(f"{path}: {msg}" for path, msg in offenders)
        )


class TestTier1HttpConfigBlock:
    """Tier 1: the new top-level http-config block. Listener-only behavior:
    trust_x_forwarded_for, block_useragents (fnmatch globs), and default
    response headers.
    """

    _SKELETON = """
http-get {
    set uri "/";
    client { metadata { base64; header "Cookie"; } }
    server { output { base64; print; } }
}

http-post {
    set uri "/submit.php";
    client { id { netbios; parameter "id"; } output { base64; print; } }
    server { output { base64; print; } }
}

http-stager {
    set uri_x86 "/a";
    set uri_x64 "/b";
    client { metadata { base64; header "Cookie"; } }
    server { output { base64; print; } }
}
"""

    def _ingest(self, http_config_block: str) -> Profile:
        p = Profile()
        p.ingest(content=http_config_block + self._SKELETON)
        return p

    def test_default_trust_x_forwarded_for_is_false(self):
        # CRITICAL: trust_x_forwarded_for defaulting to True would be a
        # spoofing vector. This test guards the secure default.
        p = Profile()
        assert p.http_config.trust_x_forwarded_for is False
        assert isinstance(p.http_config.trust_x_forwarded_for, bool)

    def test_default_block_useragents_empty(self):
        p = Profile()
        # Stored as a tuple post-Tier-1 second-pass review so the listener
        # can consume it without re-normalizing.
        assert p.http_config.block_useragents == ()

    def test_default_headers_empty(self):
        p = Profile()
        assert p.http_config.headers == []
        assert p.http_config.header_order == []

    def test_trust_x_forwarded_for_true_parsed_as_bool(self):
        p = self._ingest('http-config { set trust_x_forwarded_for "true"; }\n')
        assert p.http_config.trust_x_forwarded_for is True

    def test_trust_x_forwarded_for_false_parsed_as_bool(self):
        p = self._ingest('http-config { set trust_x_forwarded_for "false"; }\n')
        assert p.http_config.trust_x_forwarded_for is False

    def test_trust_x_forwarded_for_accepts_truthy_aliases(self):
        # CS-vintage profiles use "1", "yes", "on" interchangeably with
        # "true" — and any case combination. _TRUTHY_LITERALS is the
        # single source of truth; if a future refactor narrows the check,
        # operator profiles silently regress to insecure-False (which is
        # the secure direction, but the operator's intent is ignored).
        for truthy in ("true", "TRUE", "True", "yes", "Yes", "on", "ON", "1"):
            p = self._ingest(
                f'http-config {{ set trust_x_forwarded_for "{truthy}"; }}\n'
            )
            assert p.http_config.trust_x_forwarded_for is True, truthy

    def test_block_useragents_splits_comma_separated_globs(self):
        # Shipped CS profiles ship comma-separated globs:
        #   set block_useragents "curl*,lynx*,wget*";
        # Stored as a lowercase tuple — normalization happens at parse
        # time so the listener does not have to lowercase per request.
        p = self._ingest('http-config { set block_useragents "curl*,lynx*,wget*"; }\n')
        assert p.http_config.block_useragents == ("curl*", "lynx*", "wget*")

    def test_block_useragents_lowercases_and_dedupes(self):
        # Second-pass review concern: a duplicate `set block_useragents`
        # value used to produce two scans per request. Normalize at the
        # type boundary so dedup + lowercase happens once. Order is
        # preserved (first occurrence wins).
        p = self._ingest(
            'http-config { set block_useragents "Curl*,CURL*,wget*,curl*"; }\n'
        )
        assert p.http_config.block_useragents == ("curl*", "wget*")

    def test_block_useragents_trims_whitespace(self):
        p = self._ingest(
            'http-config { set block_useragents " curl* , lynx* , wget* "; }\n'
        )
        assert p.http_config.block_useragents == ("curl*", "lynx*", "wget*")

    def test_header_directive_accumulates_name_value_tuples(self):
        p = self._ingest(
            "http-config {\n"
            '    header "Server" "Apache";\n'
            '    header "X-Custom" "yes";\n'
            "}\n"
        )
        assert p.http_config.headers == [("Server", "Apache"), ("X-Custom", "yes")]

    def test_header_directive_with_crlf_in_name_or_value_is_dropped(self, caplog):
        # Drop the whole directive at parse time when either the name or
        # the value contains CR/LF — without this, the after_request merge
        # in the Flask listener becomes a header-injection vector and we
        # depend on Werkzeug's response-finalize check for safety.
        caplog.set_level("WARNING")
        p = self._ingest(
            "http-config {\n"
            '    header "X-Good" "fine";\n'
            '    header "X-CRLF" "v1\\r\\nInjected: bad";\n'
            '    header "X-LF-Only" "v2\\nInjected: bad";\n'
            '    header "X-CR-Only" "v3\\rInjected: bad";\n'
            '    header "Bad\\r\\nX-Smuggled: 1" "x";\n'
            '    header "Bad\\nName" "x";\n'
            '    header "X-After" "also-fine";\n'
            "}\n"
        )
        assert p.http_config.headers == [
            ("X-Good", "fine"),
            ("X-After", "also-fine"),
        ], "CRLF in either header name OR value must drop the directive"
        # Match on the invariant phrase the guard emits, not on "CRLF"
        # substrings — keeps the test stable across log-message wording.
        # Names are logged via %r so control chars appear as escapes; match
        # the repr() form so the assertion is exact for both shapes.
        guard_warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "WARNING" and "header injection guard" in r.getMessage()
        ]
        dropped_offenders = {
            offender
            for offender in (
                "X-CRLF",
                "X-LF-Only",
                "X-CR-Only",
                "Bad\r\nX-Smuggled: 1",
                "Bad\nName",
            )
            if any(repr(offender) in w for w in guard_warnings)
        }
        assert dropped_offenders == {
            "X-CRLF",
            "X-LF-Only",
            "X-CR-Only",
            "Bad\r\nX-Smuggled: 1",
            "Bad\nName",
        }, (
            f"expected a header-injection WARNING naming each dropped "
            f"directive, got {dropped_offenders} from {guard_warnings}"
        )

    def test_deserialize_rejects_crlf_smuggled_via_stored_blob(self, caplog):
        # Symmetric to the parse-time guard: a hand-edited DB row, an
        # older serialized blob, or a future transport (YAML) carrying
        # ["X-Smuggled\r\nInjected: 1", "x"] in the headers list must
        # NOT bypass the parse-time check and land in c.headers — that
        # would re-expose the Flask after_request merge to header
        # injection through the deserialize path.
        caplog.set_level("WARNING")
        c = HttpConfig._deserialize(
            {
                "headers": [
                    ["X-Good", "fine"],
                    ["X-Smuggled\r\nInjected: 1", "ok"],
                    ["X-After", "v\nlf-in-value"],
                    ["X-Clean", "also-fine"],
                ],
            }
        )
        assert c.headers == [
            ("X-Good", "fine"),
            ("X-Clean", "also-fine"),
        ], "CRLF-bearing headers in serialized data must be dropped on deserialize"
        guard_warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "WARNING" and "header injection guard" in r.getMessage()
        ]
        assert any(
            "X-Smuggled" in repr(w) or "X-Smuggled" in w for w in guard_warnings
        ), f"expected WARNING naming the smuggled name, got: {guard_warnings}"
        assert any("X-After" in w for w in guard_warnings), (
            f"expected WARNING naming the LF-in-value offender, got: {guard_warnings}"
        )

    def test_header_order_directive_splits_comma_list(self):
        p = self._ingest(
            'http-config { set headers "Server, Content-Type, Cache-Control"; }\n'
        )
        assert p.http_config.header_order == [
            "Server",
            "Content-Type",
            "Cache-Control",
        ]

    def test_clone_preserves_http_config(self):
        p = self._ingest(
            "http-config {\n"
            '    set trust_x_forwarded_for "true";\n'
            '    set block_useragents "curl*,wget*";\n'
            '    header "Server" "Apache";\n'
            "}\n"
        )
        clone = p._clone()
        assert clone.http_config.trust_x_forwarded_for is True
        assert clone.http_config.block_useragents == ("curl*", "wget*")
        assert clone.http_config.headers == [("Server", "Apache")]

    def test_serialize_roundtrip_preserves_http_config(self):
        p = self._ingest(
            "http-config {\n"
            '    set trust_x_forwarded_for "true";\n'
            '    set block_useragents "curl*";\n'
            '    header "X-Empire" "yes";\n'
            "}\n"
        )
        rt = Profile._deserialize(p._serialize())
        assert rt.http_config.trust_x_forwarded_for is True
        assert rt.http_config.block_useragents == ("curl*",)
        assert rt.http_config.headers == [("X-Empire", "yes")]


class TestTier1HttpsCertificateBlock:
    """Parser coverage for the new top-level ``https-certificate`` block.

    Tier 1 lands the parser only. Listener-side behavior (the startup
    collision WARNING when an https-certificate block is paired with an
    HTTPS listener) is a separate concern that would require Flask
    test-client scaffolding; not covered here.
    """

    _SKELETON = TestTier1HttpConfigBlock._SKELETON

    def _ingest(self, cert_block: str) -> Profile:
        p = Profile()
        p.ingest(content=cert_block + self._SKELETON)
        return p

    def test_default_is_default_returns_true(self):
        # Profile() with no https-certificate block in the source must
        # report is_default()==True so the listener does NOT fire the
        # collision warning. After the second-pass review fix, this is
        # a declaration predicate (was the block parsed?) rather than
        # a content predicate (are all fields None?).
        p = Profile()
        assert p.https_certificate.is_default() is True
        assert p.https_certificate.is_unconfigured() is True

    def test_empty_block_is_treated_as_declared(self):
        # An empty `https-certificate { }` block IS a declaration — the
        # operator wrote it, even if every directive is missing. The
        # listener wants to warn in this case so an operator who typo'd
        # every cert directive sees the diagnostic. is_default() must
        # therefore return False even though every field is None.
        p = self._ingest("https-certificate { }\n")
        assert p.https_certificate.is_default() is False
        assert all(
            getattr(p.https_certificate, f) is None
            for f in (
                "cn",
                "o",
                "ou",
                "c",
                "l",
                "st",
                "validity",
                "keystore",
                "password",
            )
        )

    def test_is_default_flips_on_any_single_field(self):
        # Per-field parametrize: setting any one field individually must
        # flip is_default() to False. Without this, a narrowed-scope
        # refactor that checks only `cn` (say) would silently pass the
        # all-fields test while missing other declarations.
        for field, value in [
            ("CN", "x"),
            ("O", "x"),
            ("OU", "x"),
            ("C", "US"),
            ("L", "x"),
            ("ST", "x"),
            ("validity", "30"),
            ("keystore", "/k.p12"),
            ("password", "p"),
        ]:
            p = self._ingest(f'https-certificate {{ set {field} "{value}"; }}\n')
            assert p.https_certificate.is_default() is False, (
                f"is_default() should be False after `set {field}`"
            )

    def test_parses_full_subject_dn(self):
        p = self._ingest(
            "https-certificate {\n"
            '    set CN "example.com";\n'
            '    set O "Example LLC";\n'
            '    set OU "ops";\n'
            '    set C "US";\n'
            '    set L "Los Angeles";\n'
            '    set ST "CA";\n'
            '    set validity "365";\n'
            "}\n"
        )
        cert = p.https_certificate
        assert cert.cn == "example.com"
        assert cert.o == "Example LLC"
        assert cert.ou == "ops"
        assert cert.c == "US"
        assert cert.l == "Los Angeles"
        assert cert.st == "CA"
        assert cert.validity == 365  # noqa: PLR2004
        assert isinstance(cert.validity, int)
        assert cert.is_default() is False

    def test_keystore_and_password_parsed(self):
        p = self._ingest(
            "https-certificate {\n"
            '    set keystore "/etc/empire/keystore.p12";\n'
            '    set password "hunter2";\n'
            "}\n"
        )
        assert p.https_certificate.keystore == "/etc/empire/keystore.p12"
        assert p.https_certificate.password == "hunter2"

    def test_invalid_validity_does_not_crash(self):
        # Operator typo shouldn't ruin a profile load — we log and skip.
        p = self._ingest(
            'https-certificate { set validity "not-a-number"; set CN "x"; }\n'
        )
        assert p.https_certificate.validity is None
        assert p.https_certificate.cn == "x"

    def test_clone_preserves_https_certificate(self):
        p = self._ingest('https-certificate { set CN "clone.test"; set O "x"; }\n')
        clone = p._clone()
        assert clone.https_certificate.cn == "clone.test"
        assert clone.https_certificate.o == "x"

    def test_serialize_roundtrip_preserves_https_certificate(self):
        p = self._ingest('https-certificate { set CN "rt.test"; set validity "30"; }\n')
        rt = Profile._deserialize(p._serialize())
        assert rt.https_certificate.cn == "rt.test"
        assert rt.https_certificate.validity == 30  # noqa: PLR2004

    def test_blocks_dont_leak_set_directives_to_profile_top_level(self):
        # Regression guard against the pyparsing ZeroOrMore resync
        # behavior that, pre-Tier 1, caused `set CN "..."` directives
        # inside an https-certificate block to leak as top-level set
        # directives on the Profile object.
        #
        # The previous version of this test scanned caplog for WARNING
        # records containing "unknown directive" — but every cert
        # directive (cn/o/ou/c/l/st/...) is in the
        # _ACCEPTED_BUT_IGNORED_SET_KEYS allow-list, so a leak would
        # have produced INFO logs, not WARNINGs. That test would have
        # passed even if the entire HttpsCertificate block parser were
        # ripped out.
        #
        # The fix is to assert positively: after parsing, the values
        # must live on `p.https_certificate.*` AND must NOT have been
        # setattr'd to the top-level Profile object via the catch-all
        # path.
        p = self._ingest(
            "https-certificate {\n"
            '    set CN "leakage.test";\n'
            '    set O "wat";\n'
            '    set keystore "/etc/store";\n'
            "}\n"
        )

        # Positive: the block parser captured the directives.
        assert p.https_certificate.cn == "leakage.test"
        assert p.https_certificate.o == "wat"
        assert p.https_certificate.keystore == "/etc/store"

        # Negative: the directives did NOT leak as top-level Profile
        # attributes. If the block parser were removed and the catch-all
        # at Profile._apply_set_directive picked these up instead, the
        # accepted-but-ignored path would `setattr(self, "cn", ...)` on
        # the Profile object. Those assertions break that regression
        # explicitly.
        for leaked_key in ("cn", "o", "keystore"):
            assert getattr(p, leaked_key, None) is None, (
                f"https-certificate `set {leaked_key}` leaked to Profile.{leaked_key}"
            )

    def test_deserialize_validity_malformed_value_does_not_crash(self, caplog):
        # Second-pass review finding: HttpsCertificate._deserialize used
        # to call int() without try/except, so a malformed validity value
        # on a round-trip (hand-edited DB row, stale stored profile)
        # raised ValueError → caught by Profile._deserialize's broad
        # except → re-raised as MalleableError → entire listener start
        # fails. Mirror the parse-side guard so the same bad value
        # logs+drops in both paths AND emits a WARNING so operators can
        # distinguish a drop-due-to-malformed from a genuine missing key
        # (both surface as validity=None downstream in the listener's
        # cert-collision warning).
        caplog.set_level("WARNING")
        c = HttpsCertificate._deserialize({"validity": "not-a-number", "cn": "x"})
        assert c.validity is None
        assert c.cn == "x"
        drop_warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "WARNING"
            and "not-a-number" in r.getMessage()
            and "validity" in r.getMessage()
        ]
        assert drop_warnings, (
            "expected a WARNING naming the malformed value so operators "
            f"can correlate it with the downstream validity=None signal; "
            f"saw: {[r.getMessage() for r in caplog.records]}"
        )

    def test_deserialize_was_declared_string_does_not_silently_flip(self):
        # Mirrors the host_stage / trust_xff guards: a stored profile
        # whose _was_declared round-tripped as the *string* "false" must
        # not flip back to True via bool("false"), which would silently
        # fire the cert-collision WARNING on every HTTPS listener start
        # even for profiles that never declared the block.
        c = HttpsCertificate._deserialize({"_was_declared": "false"})
        assert c._was_declared is False
        # And the genuine declaration path still flips to True.
        c2 = HttpsCertificate._deserialize({"_was_declared": True, "cn": "x"})
        assert c2._was_declared is True

    def test_deserialize_trust_xff_string_does_not_silently_flip(self):
        # Second-pass review finding: HttpConfig._deserialize used
        # bool(data.get(...)) which mapped the *string* "false" to True
        # (any non-empty string is truthy). A JSON round-trip that
        # stringified the bool would silently flip the security default.
        for truthy_str in ("true", "True", "1", "yes", "on"):
            c = HttpConfig._deserialize({"trust_x_forwarded_for": truthy_str})
            assert c.trust_x_forwarded_for is True, truthy_str
        for falsey_str in ("false", "False", "0", "no", "off", "", "definitely-not"):
            c = HttpConfig._deserialize({"trust_x_forwarded_for": falsey_str})
            assert c.trust_x_forwarded_for is False, falsey_str
        # And the genuine bool path:
        assert (
            HttpConfig._deserialize(
                {"trust_x_forwarded_for": True}
            ).trust_x_forwarded_for
            is True
        )
        assert (
            HttpConfig._deserialize(
                {"trust_x_forwarded_for": False}
            ).trust_x_forwarded_for
            is False
        )


class TestCoerceHelpers:
    """Direct coverage for the module-level coercion helpers. The wired
    call sites have their own tests; these guard the helpers' invariants
    so a future refactor can't quietly drop the defensive logging that
    distinguishes a malformed-input drop from a missing-input default.
    """

    def test_coerce_bool_unexpected_type_logs_and_returns_default(self, caplog):
        # Hand-edited DB rows, future YAML transports, or buggy
        # serialization paths can land non-bool/non-str/non-None types
        # (lists, dicts, ints from boolean-typed SQL columns) in a
        # serialized profile. Without logging, _coerce_bool([]) silently
        # yielded False and _coerce_bool({"x": 1}) silently yielded True
        # — for security-critical fields like host_stage this hid a
        # malformed-input drop behind a plausible default value.
        caplog.set_level("WARNING")
        for unexpected in ([], {}, [0], object()):
            caplog.clear()
            assert _coerce_bool(unexpected, default=True) is True, unexpected
            warnings = [
                r.getMessage()
                for r in caplog.records
                if r.levelname == "WARNING" and "_coerce_bool" in r.getMessage()
            ]
            assert warnings, (
                f"expected WARNING for unexpected type {type(unexpected).__name__}, "
                f"saw: {[r.getMessage() for r in caplog.records]}"
            )

    def test_coerce_bool_known_types_do_not_log(self, caplog):
        # The defensive WARNING must not fire on the documented happy paths:
        # genuine bool, truthy/falsy str vocabulary, None (defaults).
        caplog.set_level("WARNING")
        assert _coerce_bool(True) is True
        assert _coerce_bool(False) is False
        assert _coerce_bool("true") is True
        assert _coerce_bool("false") is False
        assert _coerce_bool("garbage") is False
        assert _coerce_bool(None, default=True) is True
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert warnings == [], (
            f"happy-path coercion must not WARN, got: {[r.getMessage() for r in warnings]}"
        )


class TestStagerDefaultUri:
    """`/init/` is a fallback for profiles that declare no stager URI. It
    must not be unioned onto URIs a profile's http-stager block declares."""

    @staticmethod
    def _profile(content: str) -> Profile:
        profile = Profile()
        profile.ingest(content=content)
        return profile

    def test_stager_block_with_uri_does_not_get_init(self):
        profile = self._profile(
            """
            http-stager {
                set uri "/stage";
                client { header "Accept" "*/*"; }
                server { header "Server" "nginx"; }
            }
            """
        )
        assert profile.stager.client.uris == ["/stage"]

    def test_no_stager_block_gets_init(self):
        profile = self._profile(
            """
            http-get {
                set uri "/get";
                client { header "Accept" "*/*"; }
                server { header "Server" "nginx"; }
            }
            """
        )
        assert profile.stager.client.uris == ["/init/"]

    def test_stager_block_without_uri_gets_init(self):
        profile = self._profile(
            """
            http-stager {
                server { header "Server" "nginx"; }
            }
            """
        )
        assert profile.stager.client.uris == ["/init/"]

    @pytest.mark.parametrize("content", ["", "# only a comment\n"])
    def test_empty_profile_gets_init(self, content):
        assert self._profile(content).stager.client.uris == ["/init/"]
