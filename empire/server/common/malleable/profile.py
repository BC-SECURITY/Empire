import base64
import json
import logging
import string

from pyparsing import *

from .implementation import Get, Post, Stager
from .transaction import MalleableRequest, MalleableResponse
from .transformation import Container, Terminator, Transform
from .utility import MalleableError, MalleableObject, MalleableUtil

log = logging.getLogger(__name__)

# Schema version for the JSON profile blob consumed by C#/Go agents.
# Bump when making a backwards-incompatible change — both Sharpire and
# Gopire parse `v` and will refuse unknown versions.
_AGENT_PROFILE_SCHEMA_VERSION = 1

# Top-level `set X "Y";` directives the parser honors. Anything in this set
# goes through normal attribute assignment (which also runs property setters
# like Profile.useragent).
_WIRED_UP_SET_KEYS = frozenset(
    {
        "useragent",
        "sleeptime",
        "jitter",
        "host_stage",
        "sample_name",
    }
)

# `set X "Y";` directives present in shipped Cobalt Strike profiles that
# Empire accepts but does not yet act on. Stored on the instance for
# inspection / forward-compat but not used by the runtime.
#
# IMPORTANT: this set must cover *every* `set` keyword used by shipped
# profiles under empire/server/data/profiles/. The catch is that pyparsing's
# ZeroOrMore in Profile._pattern() greedily resyncs around unrecognised
# blocks (http-config, https-certificate, stage, process-inject, post-ex,
# dns-beacon, …), so `set` directives *inside* those blocks leak out and
# parse as top-level directives. Until Tiers 1/3/4 add real block parsers,
# we list those leaked keys here so the parser stays quiet on existing
# profiles. The grouping comments mark which roadmap tier should drain
# the key out of this set into a real wiring.
#
# Audit: `grep -rhE '^\s*set [A-Za-z_]' empire/server/data/profiles/ \
#   | grep -oE 'set [A-Za-z_][A-Za-z_0-9]*' | awk '{print $2}' | sort -u`
# Re-run when adding a new shipped profile and reconcile with this set —
# the TestShippedProfilesAllowList test will fail if drift goes uncaught.
_ACCEPTED_BUT_IGNORED_SET_KEYS = frozenset(
    {
        # dns-beacon block / DNS C2 (roadmap Tier 5 — deferred)
        "beacon",
        "data_jitter",
        "dns_idle",
        "dns_max_txt",
        "dns_sleep",
        "dns_stager_prepend",
        "dns_stager_subhost",
        "dns_ttl",
        "get_a",
        "get_aaaa",
        "get_txt",
        "maxdns",
        "name",  # DNS beacon name; case-insensitive lowercase here
        "ns_response",
        "put_metadata",
        "put_output",
        # https-certificate block (roadmap Tier 1)
        "c",
        "cn",
        "keystore",
        "l",
        "o",
        "ou",
        "password",
        "st",
        "validity",
        # http-config block (roadmap Tier 1)
        "block_useragents",
        "headers",
        "trust_x_forwarded_for",
        "verb",
        # stage block (roadmap Tier 3)
        "checksum",
        "cleanup",
        "compile_time",
        "entry_point",
        "image_size_x64",
        "image_size_x86",
        "magic_mz_x64",
        "magic_mz_x86",
        "magic_pe",
        "module_x64",
        "module_x86",
        "obfuscate",
        "rich_header",
        "sleep_mask",
        "smartinject",
        "stomppe",
        "userwx",
        # http-stager block (roadmap Tier 2 — stager-block transforms / URIs)
        "uri",
        "uri_x64",
        "uri_x86",
        # process-inject block (roadmap Tier 4)
        "allocator",
        "hijack_remote_thread",
        "min_alloc",
        "spawnto",
        "spawnto_x64",
        "spawnto_x86",
        "startrwx",
        # post-ex block (roadmap Tier 3)
        "amsi_disable",
        "keylogger",
        "pipename",
        "pipename_stager",
        "thread_hint",
        # SMB / TCP / SSH transports (out of scope for current tiers)
        "smb_frame_header",
        "ssh_banner",
        "ssh_pipename",
        "tcp_frame_header",
        "tcp_port",
    }
)

# Type normalization for wired-up scalar keys. The parser produces strings,
# so without this `set host_stage "false";` would store the truthy string
# "false" — silently wrong. `set sleeptime "60000";` historically worked
# only because downstream code re-wrapped it in int().
_BOOL_SET_KEYS = frozenset({"host_stage"})
_INT_SET_KEYS = frozenset({"sleeptime", "jitter"})

# Truthy literal values accepted for boolean `set` directives. Anything else
# (including the empty string) is treated as False — matching Cobalt Strike's
# documented convention for boolean profile fields.
_TRUTHY_LITERALS = frozenset({"true", "1", "yes", "on"})


def _normalize_set_value(key: str, raw: str):
    """Coerce a string-valued `set <key> "<raw>";` value to its typed form.

    Booleans are case-insensitive: only the literals in _TRUTHY_LITERALS map
    to True. Integers raise no exception — if the operator wrote a non-numeric
    value, ``int()`` will throw and the caller logs + drops the directive.
    """
    if key in _BOOL_SET_KEYS:
        return raw.strip().lower() in _TRUTHY_LITERALS
    if key in _INT_SET_KEYS:
        return int(raw)
    return raw


def _coerce_bool(raw, default: bool = False) -> bool:
    """Coerce a serialized boolean (Python bool OR truthy-literal string)
    to bool, using the same vocabulary as the parser. Centralized so that
    `_deserialize` paths and runtime parse paths agree — a JSON round-trip
    that stringifies a Python ``False`` to ``"false"`` must not silently
    flip back to ``True`` via ``bool("false")``.

    Unexpected types (list, dict, custom object) log a WARNING and return
    ``default`` — mirrors `_coerce_optional_int` so a malformed-input drop
    is always visible to operators, not silently coerced via ``bool(raw)``
    where ``bool([])`` is False and ``bool({"x": 1})`` is True.
    """
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in _TRUTHY_LITERALS
    if raw is None:
        return default
    log.warning(
        "malleable profile: _coerce_bool received unexpected type %s (%r); "
        "returning default=%r",
        type(raw).__name__,
        raw,
        default,
    )
    return default


def _coerce_optional_int(raw, *, context: str):
    """Coerce a value to ``int`` or ``None``, logging+dropping on failure.
    Used by both parse-time and deserialize-time validity handling so the
    two paths cannot diverge (a typo at parse time logs a warning; the same
    malformed value flowing back through ``_deserialize`` must do the same
    rather than raising ``MalleableError`` and killing listener startup).
    """
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        # Spell out the downstream effect so an operator inspecting a
        # later "validity=None" cert-collision warning can grep back to
        # the source (malformed input dropped) rather than mistaking it
        # for an omitted directive.
        log.warning(
            "malleable profile: %s=%r is not an int; "
            "dropping value (will appear as None to downstream consumers)",
            context,
            raw,
        )
        return None


def _header_pair_is_safe(name, value, *, source: str) -> bool:
    """True if (name, value) is safe to merge into a response. Rejects
    CRLF in either part to close header-injection through the Flask
    ``after_request`` merge. Shared by parse and deserialize so a
    hand-edited DB row cannot bypass the parse-time guard.
    """
    if any(
        isinstance(part, str) and ("\r" in part or "\n" in part)
        for part in (name, value)
    ):
        log.warning(
            "malleable profile (%s): dropping header %r — name or value contains CRLF (header injection guard)",
            source,
            name,
        )
        return False
    return True


# Transform.type -> JSON "op" string. NONE is intentionally absent so it
# falls through to the "skip" branch in the serializer.
#
# NOTE on append/prepend: the "value" field is emitted as base64 of the
# raw bytes (latin-1 in the Python model). A plain JSON string would
# UTF-8-encode any high-bit byte and silently grow it from 1 byte to 2,
# breaking byte-exact parity with the PowerShell/Python server transforms
# on the other side. Both Sharpire (C#) and Gopire (Go) base64-decode
# this field before concatenation.
_TRANSFORM_OP_NAMES = {
    Transform.APPEND: "append",
    Transform.PREPEND: "prepend",
    Transform.BASE64: "base64",
    Transform.BASE64URL: "base64url",
    Transform.NETBIOS: "netbios",
    Transform.NETBIOSU: "netbiosu",
    Transform.MASK: "mask",
}

# Terminator.type -> JSON "type" string.
_TERMINATOR_TYPE_NAMES = {
    Terminator.HEADER: "header",
    Terminator.PRINT: "print",
    Terminator.PARAMETER: "parameter",
    Terminator.URIAPPEND: "uri-append",
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# TOP-LEVEL CONFIG BLOCKS
#
# http-config + https-certificate are listener-only blocks (no agent
# wire-format impact). The Tier 1 wiring is parse-and-honor where
# implementable today and parse-but-defer where it requires
# infrastructure that isn't in this tree yet (certificate generation).
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class HttpConfig(MalleableObject):
    """The http-config block: listener-wide HTTP behavior.

    Cobalt Strike's http-config block applies to every HTTP response the
    listener emits, regardless of which http-get/http-post/http-stager
    URI the request hit.

    Attributes:
        trust_x_forwarded_for (bool): when True, the listener honors the
            ``X-Forwarded-For`` header and treats the first entry as the
            real client IP. **Defaults to False** — defaulting to True is
            a spoofing vector since the header is attacker-controllable
            unless there is a trusted upstream proxy.
        block_useragents (tuple[str, ...]): fnmatch-style globs
            (``curl*``, ``wget*``) normalized to lowercase + deduplicated
            at parse time. The listener applies them case-insensitively
            against the request ``User-Agent``; a match returns 404
            before any agent logic runs. Globs — not full regex — to
            avoid operator-supplied ReDoS patterns from public CS
            profiles. The listener also caps UA bytes before matching.
        headers (list[tuple[str, str]]): default response headers merged
            into every non-blocked Flask response. (The UA-block 404 path
            intentionally bypasses this merge to avoid signaling that
            blocking is in effect.)
        header_order (list[str]): the ``set headers "A, B, C";``
            directive declares ordering for the named headers. Recorded
            for inspection; the underlying Flask/Werkzeug stack does not
            expose a way to enforce ordering, so the listener emits an
            INFO note at startup when this is declared.

    Note on `_parse` semantics: `header` directives **accumulate** (each
    occurrence appends), while `set block_useragents` and `set headers`
    **replace** (a later occurrence overrides the earlier value, matching
    CS profile conventions).
    """

    trust_x_forwarded_for: bool
    block_useragents: tuple[str, ...]
    headers: list[tuple[str, str]]
    header_order: list[str]

    def _defaults(self):
        super()._defaults()
        # Security-relevant default: must stay False unless an operator
        # explicitly opts in via the profile.
        self.trust_x_forwarded_for = False
        self.block_useragents = ()
        self.headers = []
        self.header_order = []

    def _clone(self):
        new = super()._clone()
        new.trust_x_forwarded_for = self.trust_x_forwarded_for
        # tuple is immutable; sharing the reference is safe and cheap.
        new.block_useragents = self.block_useragents
        new.headers = [(name, value) for name, value in self.headers]
        new.header_order = list(self.header_order)
        return new

    def _serialize(self):
        return dict(
            list(super()._serialize().items())
            + list(
                {
                    "trust_x_forwarded_for": self.trust_x_forwarded_for,
                    "block_useragents": list(self.block_useragents),
                    "headers": [list(pair) for pair in self.headers],
                    "header_order": list(self.header_order),
                }.items()
            )
        )

    @classmethod
    def _deserialize(cls, data):
        c = super()._deserialize(data)
        if data:
            # Use the shared coercer so a JSON round-trip that stringifies
            # a Python bool does not silently flip the security default.
            # `bool("false")` is True — without this helper, that footgun
            # would land trust_x_forwarded_for=True via the deserialize
            # path while the parse path correctly maps "false" → False.
            c.trust_x_forwarded_for = _coerce_bool(
                data.get("trust_x_forwarded_for", False), default=False
            )
            c.block_useragents = cls._normalize_block_useragents(
                data.get("block_useragents", []) or []
            )
            c.headers = [
                (pair[0], pair[1])
                for pair in data.get("headers", [])
                if isinstance(pair, (list, tuple))
                and len(pair) == 2
                and _header_pair_is_safe(pair[0], pair[1], source="deserialize")
            ]
            c.header_order = list(data.get("header_order", []))
        return c

    @staticmethod
    def _normalize_block_useragents(globs) -> tuple[str, ...]:
        """Lowercase + dedupe (order-preserving) so the listener consumes
        a ready-to-match list. Living in the type rather than the listener
        means a future second consumer (stats endpoint, alternate
        transport) cannot forget to normalize and silently behave wrong.
        """
        seen: dict[str, None] = {}  # dict preserves insertion order
        for raw in globs:
            if not isinstance(raw, str):
                continue
            cleaned = raw.strip().lower()
            if cleaned:
                seen.setdefault(cleaned, None)
        return tuple(seen)

    @classmethod
    def _pattern(cls):
        # Follows the Get/Post/Stager convention: the literal block name
        # is a sibling token followed by a Group wrapping the brace body.
        # Wrapping the *whole* pattern in Group() instead puts the literal
        # inside the group and collapses two tokens into one at the
        # outer ZeroOrMore, which then breaks Profile._parse's pair
        # iteration.
        return Literal("http-config") + Group(
            Suppress("{")
            + ZeroOrMore(
                cls.COMMENT
                | (Literal("set") + Group(cls.FIELD + cls.VALUE) + cls.SEMICOLON)
                | (Literal("header") + Group(cls.VALUE + cls.VALUE) + cls.SEMICOLON)
            )
            + Suppress("}")
        )

    def _parse(self, data):
        if not data:
            return
        for i in range(0, len(data), 2):
            item = data[i]
            arg = data[i + 1] if len(data) > i + 1 else None
            if not (item and arg):
                continue
            lit = item.lower()
            if lit == "set" and len(arg) > 1:
                key = arg[0].lower()
                value = arg[1]
                if key == "trust_x_forwarded_for":
                    self.trust_x_forwarded_for = _coerce_bool(value)
                elif key == "block_useragents":
                    self.block_useragents = self._normalize_block_useragents(
                        p.strip() for p in value.split(",")
                    )
                elif key == "headers":
                    # CS uses this to declare header ORDER, not values.
                    self.header_order = [
                        p.strip() for p in value.split(",") if p.strip()
                    ]
                # Other set keys are silently dropped (forward-compat
                # with future CS directives — no log because shipped
                # profiles legitimately use keys we have not yet wired
                # up, and an INFO/WARNING per profile load would be
                # noise).
            elif lit == "header" and len(arg) > 1:
                name = arg[0]
                value = arg[1]
                if name and _header_pair_is_safe(name, value, source="parse"):
                    self.headers.append((name, value))


class HttpsCertificate(MalleableObject):
    """The https-certificate block: TLS cert fields for the listener.

    Parses CS-style ``https-certificate { set CN "..."; ... }`` blocks
    into a typed object. **Empire does not generate a TLS certificate at
    listener-start time today** — the listener loads a pre-existing PEM
    from ``CertPath`` (generated once at first server start by
    ``empire.server.utils.cert_util``), so these fields are not yet driven
    into the underlying cert.

    The listener emits a startup WARNING if a profile defines this block
    while the listener is configured for HTTPS (regardless of CertPath
    explicit-vs-default), since the operator may be expecting profile
    values to take effect — they won't, yet. Wiring it up requires
    either ephemeral cert generation at listener start (which rotates
    fingerprints on restart unless the key is persisted) or a
    deterministic key derivation — a follow-up in its own PR.

    Attributes:
        cn / o / ou / c / l / st (str | None): X.509 subject DN fields.
        validity (int | None): cert validity in days. Negative or zero
            values are accepted but flagged with an INFO log at listener
            startup since they produce non-sensical certs.
        keystore / password (str | None): optional path + password for
            pinning an externally-managed PKCS12 / JKS keystore.

    Note: `l` (locality) is the X.509 RDN abbreviation. It collides
    visually with the digit `1`; ruff's E741 is waived for this subtree.
    """

    cn: str | None
    o: str | None
    ou: str | None
    c: str | None
    l: str | None  # noqa: E741 — X.509 RDN abbreviation, intentional
    st: str | None
    validity: int | None
    keystore: str | None
    password: str | None

    # Canonical field list — drives _defaults, _clone, _serialize,
    # _deserialize, and is_default. Adding a new field once here is
    # enough; the second-pass review flagged the previous triple-list
    # duplication as an edit-cost trap.
    _ALL_FIELDS: tuple[str, ...] = (
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
    _STRING_FIELDS = frozenset(
        {"cn", "o", "ou", "c", "l", "st", "keystore", "password"}
    )

    def _defaults(self):
        super()._defaults()
        for field in self._ALL_FIELDS:
            setattr(self, field, None)
        # Tracks operator declaration explicitly so `is_default` /
        # `is_unconfigured` returns True only when the profile did NOT
        # declare an https-certificate block — distinct from "the block
        # was declared but every field failed to parse," which the
        # collision warning at listener startup needs to surface.
        self._was_declared: bool = False

    def _clone(self):
        new = super()._clone()
        for field in self._ALL_FIELDS:
            setattr(new, field, getattr(self, field))
        new._was_declared = self._was_declared
        return new

    def _serialize(self):
        payload = {field: getattr(self, field) for field in self._ALL_FIELDS}
        payload["_was_declared"] = self._was_declared
        return dict(list(super()._serialize().items()) + list(payload.items()))

    @classmethod
    def _deserialize(cls, data):
        c = super()._deserialize(data)
        if data:
            for field in cls._STRING_FIELDS:
                setattr(c, field, data.get(field))
            # Use the shared coercer so a malformed `validity` (e.g.
            # "abc" from a hand-edited DB row or stale stored profile)
            # logs+drops rather than raising up to MalleableError and
            # killing listener startup. Mirrors the parse-side guard.
            c.validity = _coerce_optional_int(
                data.get("validity"),
                context="https-certificate validity",
            )
            c._was_declared = _coerce_bool(data.get("_was_declared", False))
        return c

    @classmethod
    def _pattern(cls):
        # Same Get/Post/Stager convention as HttpConfig — literal token
        # sibling to the Group(body).
        return Literal("https-certificate") + Group(
            Suppress("{")
            + ZeroOrMore(
                cls.COMMENT
                | (Literal("set") + Group(cls.FIELD + cls.VALUE) + cls.SEMICOLON)
            )
            + Suppress("}")
        )

    def _parse(self, data):
        # The presence of a `https-certificate { ... }` block in the
        # profile flips _was_declared True even before we inspect any
        # inner directive — an empty block is still a declaration, and
        # the listener WANTS to warn about that case so an operator
        # who typo'd every cert directive sees the diagnostic.
        self._was_declared = True
        if not data:
            return
        for i in range(0, len(data), 2):
            item = data[i]
            arg = data[i + 1] if len(data) > i + 1 else None
            if not (item and arg):
                continue
            if item.lower() != "set" or len(arg) <= 1:
                continue
            key = arg[0].lower()
            value = arg[1]
            if key in self._STRING_FIELDS:
                setattr(self, key, value)
            elif key == "validity":
                self.validity = _coerce_optional_int(
                    value, context="https-certificate validity"
                )
            # Other set keys inside this block are silently dropped
            # (forward-compat with future CS directives — no log
            # because shipped profiles legitimately use cert-attribute
            # variants we have not yet enumerated).

    def is_default(self) -> bool:
        """True when the profile did NOT declare an https-certificate
        block. Used by the listener to decide whether to emit the
        startup collision warning.

        Implementation note: previously this returned True whenever every
        field was None — a content predicate. The second-pass review
        pointed out the caller wants a *declaration* predicate: an empty
        ``https-certificate { }`` block or one where every directive
        failed to parse should still produce ``False`` so the operator
        sees the warning.

        :func:`is_unconfigured` is the preferred name in new code.
        """
        return not self._was_declared

    def is_unconfigured(self) -> bool:
        """Alias for :func:`is_default`; clearer name for new call sites."""
        return self.is_default()


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# PROFILE
#
# Defining the top-layer object to be interacted with.
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class Profile(MalleableObject):
    """A class housing all the functionality of a Malleable C2 profile.

    Attributes:
        get (Get (Transaction))
        post (Post (Transaction))
        stager (Stager (Transaction))

        useragent (str, property)
        sleeptime (int) [milliseconds]
        jitter (int) [percent]
    """

    def _defaults(self):
        """Default initialization for the Profile object."""
        super()._defaults()
        self.get = Get()
        self.post = Post()
        self.stager = Stager()
        self.sleeptime = 60000
        self.jitter = 0
        # host_stage defaults True so existing profiles keep serving the
        # stager URI; operators opt out by adding `set host_stage "false";`.
        self.host_stage = True
        # sample_name is a free-form attribution tag from the profile author,
        # surfaced in the API but not used by the runtime.
        self.sample_name = None
        # Tier 1: listener-only top-level blocks. Defaults are conservative
        # (trust_x_forwarded_for=False, no blocked UAs, no extra headers,
        # no cert overrides) so an existing profile without these blocks
        # gets the same behavior as before Tier 1.
        self.http_config = HttpConfig()
        self.https_certificate = HttpsCertificate()

    def _clone(self):
        """Deep copy of the Profile object.

        Returns:
            Profile
        """
        new = super()._clone()
        new.get = self.get._clone()
        new.post = self.post._clone()
        new.stager = self.stager._clone()
        new.sleeptime = self.sleeptime
        new.jitter = self.jitter
        new.host_stage = self.host_stage
        new.sample_name = self.sample_name
        new.http_config = self.http_config._clone()
        new.https_certificate = self.https_certificate._clone()
        return new

    def _serialize(self):
        """Serialize the Profile object.

        Returns:
            dict (str, obj): Serialized data (json)
        """
        return dict(
            list(super()._serialize().items())
            + list(
                {
                    "get": self.get._serialize(),
                    "post": self.post._serialize(),
                    "stager": self.stager._serialize(),
                    "sleeptime": self.sleeptime,
                    "jitter": self.jitter,
                    "host_stage": self.host_stage,
                    "sample_name": self.sample_name,
                    "http_config": self.http_config._serialize(),
                    "https_certificate": self.https_certificate._serialize(),
                }.items()
            )
        )

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data into a Profile object.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            Profile object
        """
        profile = super()._deserialize(data)
        if data:
            try:
                profile.get = Get._deserialize(data["get"]) if "get" in data else Get()
                profile.post = (
                    Post._deserialize(data["post"]) if "post" in data else Post()
                )
                profile.stager = (
                    Stager._deserialize(data["stager"])
                    if "stager" in data
                    else Stager()
                )
                profile.sleeptime = (
                    int(data["sleeptime"]) if "sleeptime" in data else 60000
                )
                profile.jitter = int(data["jitter"]) if "jitter" in data else 0
                # Mirror the parse-side coercion so a stringified "false"
                # on a JSON round-trip (hand-edited DB row, older serialized
                # blob, future YAML transport) cannot silently flip the
                # Tier 0 stager gate back to True via bool("false") is True.
                profile.host_stage = _coerce_bool(
                    data.get("host_stage", True), default=True
                )
                profile.sample_name = data.get("sample_name")
                profile.http_config = (
                    HttpConfig._deserialize(data["http_config"])
                    if "http_config" in data
                    else HttpConfig()
                )
                profile.https_certificate = (
                    HttpsCertificate._deserialize(data["https_certificate"])
                    if "https_certificate" in data
                    else HttpsCertificate()
                )
            except Exception as e:
                MalleableError.throw(
                    cls, "_deserialize", "An error occurred: " + str(e)
                )
        return profile

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize a Profile object while parsing a file.

        Returns:
            pyparsing object
        """
        return ZeroOrMore(
            cls.COMMENT
            | (Literal("set") + Group(cls.FIELD + cls.VALUE) + cls.SEMICOLON)
            | Get._pattern()
            | Post._pattern()
            | Stager._pattern()
            | HttpConfig._pattern()
            | HttpsCertificate._pattern()
        )

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        if data:
            for group in [d for d in data if d]:
                for i in range(0, len(group), 2):
                    item = group[i]
                    arg = group[i + 1] if len(group) > i + 1 else None
                    if not item:
                        continue
                    # `set` directives need a non-empty arg (the
                    # key/value pair group). Block dispatches must
                    # still fire on an empty body — e.g. an empty
                    # `https-certificate { }` block is a meaningful
                    # declaration that flips HttpsCertificate._was_declared
                    # so the listener emits the cert-collision warning.
                    if item.lower() == "set":
                        if arg and len(arg) > 1:
                            key, value = arg[0], arg[1]
                            if key and value:
                                self._apply_set_directive(key, value)
                    elif item.lower() == "http-get":
                        self.get._parse(arg)
                    elif item.lower() == "http-post":
                        self.post._parse(arg)
                    elif item.lower() == "http-stager":
                        self.stager._parse(arg)
                    elif item.lower() == "http-config":
                        self.http_config._parse(arg)
                    elif item.lower() == "https-certificate":
                        self.https_certificate._parse(arg)
        self.stager.add_default_uri()

    def _apply_set_directive(self, key: str, raw_value: str) -> None:
        """Classify and apply a top-level `set <key> "<raw_value>";` directive.

        Three-way classifier (see module-level allow-lists):
          - wired-up keys flow through normal attribute assignment, with
            type normalization for booleans/integers so `set host_stage
            "false";` round-trips to Python ``False`` rather than the
            truthy string ``"false"``.
          - accepted-but-ignored keys land on the instance verbatim and
            emit one DEBUG log per directive (DEBUG, not INFO, because
            shipped CS profiles routinely declare keys Empire does not
            honor and INFO flooded operator consoles at the default
            log level — see inline comment at the log call).
          - unknown keys also land on the instance (preserving the
            historical catch-all behavior so no profile parse hard-fails
            on this change) but emit a WARNING.
        """
        lowered = key.lower()

        if lowered in _WIRED_UP_SET_KEYS:
            try:
                value = _normalize_set_value(lowered, raw_value)
            except (TypeError, ValueError) as exc:
                log.warning(
                    "malleable profile: dropping set %s=%r (cannot normalize: %s)",
                    key,
                    raw_value,
                    exc,
                )
                return
            setattr(self, lowered, value)
            return

        if lowered in _ACCEPTED_BUT_IGNORED_SET_KEYS:
            # DEBUG (not INFO): shipped CS profiles routinely declare keys
            # Empire does not yet honor (maxdns, compile_time, image_size_*,
            # dns_idle, userwx, …). Empire loads several profiles at startup,
            # so INFO here flooded operator consoles with non-actionable
            # messages. The directive is still attached to the instance so
            # audit tools and tests can introspect it.
            log.debug(
                "malleable profile: accepting `set %s` but Empire does not act on it yet",
                key,
            )
            setattr(self, lowered, raw_value)
            return

        log.warning(
            "malleable profile: unknown directive `set %s %r;` — storing on profile but it will not affect behavior",
            key,
            raw_value,
        )
        setattr(self, lowered, raw_value)

    @property
    def useragent(self):
        """Get the profile useragent.

        Returns:
            str: useragent
        """
        return (
            self.get.client.headers["User-Agent"]
            if "User-Agent" in self.get.client.headers
            else None
        )

    @useragent.setter
    def useragent(self, useragent):
        """Set the profile useragent.

        Args:
            useragent (str)
        """
        self.get.client.headers["User-Agent"] = useragent
        self.post.client.headers["User-Agent"] = useragent
        self.stager.client.headers["User-Agent"] = useragent

    def validate(self):
        """Validate the profile to verify it will succeed when used.

        Returns:
            bool: True if no checks fail.

        Raises:
            MalleableError: If a check fails.
        """
        host = "http://domain.com:80"
        # data = string.printable
        data = string.printable.encode("latin-1")
        for format, p in [
            ("base", self),
            ("clone", self._clone()),
            ("serialized", Profile._deserialize(self._serialize())),
        ]:
            test = p.get.construct_client(host, data)
            clone = MalleableRequest()
            clone.url = test.url
            clone.verb = test.verb
            clone.headers = test.headers
            clone.body = test.body
            if self.get.extract_client(clone) != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-get-client-metadata" % format,
                )

            test = p.get.construct_server(data)
            clone = MalleableResponse()
            clone.headers = test.headers
            clone.body = test.body
            if self.get.extract_server(clone) != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-get-server-output" % format,
                )

            test = p.post.construct_client(host, data, data)
            clone = MalleableRequest()
            clone.url = test.url
            clone.verb = test.verb
            clone.headers = test.headers
            clone.body = test.body
            id, output = self.post.extract_client(clone)
            if id != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-post-client-id" % format,
                )
            if output != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-post-client-output" % format,
                )

            test = p.post.construct_server(data)
            clone = MalleableResponse()
            clone.headers = test.headers
            clone.body = test.body
            if self.post.extract_server(clone) != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-post-server-output" % format,
                )

            test = p.stager.construct_client(host, data)
            clone = MalleableRequest()
            clone.url = test.url
            clone.verb = test.verb
            clone.headers = test.headers
            clone.body = test.body
            if self.stager.extract_client(clone) != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-stager-client-metadata" % format,
                )

            test = p.stager.construct_server(data)
            clone = MalleableResponse()
            clone.headers = test.headers
            clone.body = test.body
            if self.stager.extract_server(clone) != data:
                MalleableError.throw(
                    self.__class__,
                    "validate",
                    "Data-integrity check failed: %s-stager-server-output" % format,
                )

        if (
            set(self.get.client.uris).intersection(set(self.post.client.uris))
            or set(self.post.client.uris).intersection(set(self.stager.client.uris))
            or set(self.stager.client.uris).intersection(set(self.get.client.uris))
            or len(self.get.client.uris + (self.post.client.uris or ["/"])) == 0
            or len(self.post.client.uris + (self.stager.client.uris or ["/"])) == 0
            or len(self.stager.client.uris + (self.get.client.uris or ["/"])) == 0
            or ("/" in self.get.client.uris and len(self.post.client.uris) == 0)
            or ("/" in self.get.client.uris and len(self.stager.client.uris) == 0)
            or ("/" in self.post.client.uris and len(self.stager.client.uris) == 0)
            or ("/" in self.post.client.uris and len(self.get.client.uris) == 0)
            or ("/" in self.stager.client.uris and len(self.get.client.uris) == 0)
            or ("/" in self.stager.client.uris and len(self.post.client.uris) == 0)
        ):
            MalleableError.throw(
                self.__class__,
                "validate",
                "Cannot have duplicate uris: %s - %s - %s"
                % (
                    self.get.client.uris or ["/"],
                    self.post.client.uris or ["/"],
                    self.stager.client.uris or ["/"],
                ),
            )

        return True

    def serialize_for_agent(self) -> str:
        """Serialize this profile to a compact JSON blob for runtime consumption
        by non-PowerShell/Python agents (C# / Sharpire, Go / Gopire).

        The result is inlined into stager templates, so it is emitted with
        ``separators=(",", ":")`` — no whitespace padding. See the schema
        documentation and ``_AGENT_PROFILE_SCHEMA_VERSION`` for the versioned
        contract with downstream agent parsers.

        Returns:
            str: Compact JSON blob.
        """
        payload = {
            "v": _AGENT_PROFILE_SCHEMA_VERSION,
            "sleep": int(self.sleeptime),
            "jitter": int(self.jitter),
            "sections": {
                "stager": self._section_for_agent(
                    self.stager,
                    include_client_output=False,
                ),
                "get": self._section_for_agent(
                    self.get,
                    include_client_output=False,
                ),
                "post": self._section_for_agent(
                    self.post,
                    include_client_output=True,
                ),
            },
        }
        return json.dumps(payload, separators=(",", ":"))

    def _section_for_agent(self, transaction, include_client_output: bool) -> dict:
        """Build the per-section dict (stager / get / post).

        ``include_client_output`` is True only for the Post section, which
        is the only transaction whose client carries both a routing packet
        and a task-result payload.
        """
        client = transaction.client
        server = transaction.server

        # Post stores its routing packet in `.id`; Get/Stager store session
        # metadata in `.metadata`. In the agent-facing JSON both are the
        # "metadata" container — agents don't care about Empire's internal
        # naming.
        client_metadata = getattr(client, "metadata", None)
        if client_metadata is None:
            client_metadata = getattr(client, "id", Container())

        client_block = {
            "verb": client.verb,
            "uris": list(client.uris) if client.uris else [],
            "headers": dict(client.headers) if client.headers else {},
            "parameters": dict(client.parameters) if client.parameters else {},
            # body is base64-encoded bytes for the same reason as
            # append/prepend value — cover payloads can contain high-bit
            # characters in real-world profiles and we want byte-exact
            # parity on the Go/C# agent side.
            "body": self._encode_bytes_for_agent(client.body),
            "metadata": self._container_for_agent(client_metadata),
        }
        if include_client_output:
            client_block["output"] = self._container_for_agent(client.output)

        server_block = {
            "headers": dict(server.headers) if server.headers else {},
            "body_prefix": self._encode_bytes_for_agent(
                getattr(server, "body_prefix", "")
            ),
            "output": self._container_for_agent(server.output),
        }

        return {"client": client_block, "server": server_block}

    @staticmethod
    def _encode_bytes_for_agent(value) -> str:
        """Base64-encode a body / body_prefix / prepend / append value so
        high-bit bytes survive the JSON UTF-8 round-trip. Accepts bytes
        or str (latin-1 fallback for str). None/"" returns "".
        """
        if value is None or value == "":
            return ""
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
        elif isinstance(value, str):
            try:
                raw = value.encode("latin-1")
            except UnicodeEncodeError:
                raw = value.encode("utf-8")
        else:
            return ""
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def _container_for_agent(container) -> dict:
        """Serialize a Container (sequence of Transforms + Terminator) to
        the agent JSON shape: ``{"transforms": [...], "terminator": {...}}``.
        """
        if container is None:
            return {
                "transforms": [],
                "terminator": {"type": "print"},
            }

        transforms = []
        for t in getattr(container, "transforms", []) or []:
            entry = Profile._transform_for_agent(t)
            if entry is not None:
                transforms.append(entry)

        return {
            "transforms": transforms,
            "terminator": Profile._terminator_for_agent(container.terminator),
        }

    @staticmethod
    def _transform_for_agent(transform):
        """Map a Transform object to its agent-JSON representation, or None
        if it should be skipped (NONE / unknown type / malformed arg).
        """
        t_type = getattr(transform, "type", Transform.NONE)
        op = _TRANSFORM_OP_NAMES.get(t_type)
        if op is None:
            # NONE or an unrecognized type — drop it rather than crash.
            return None

        arg = getattr(transform, "arg", None)

        if t_type in (Transform.APPEND, Transform.PREPEND):
            # Emit the raw bytes as base64 so high-bit values (e.g. a
            # latin-1 b"\xe9") survive the JSON UTF-8 encoding with their
            # 1-byte length intact. A plain JSON string would expand to
            # two UTF-8 bytes and desync the reverse transform on the
            # agent side.
            if arg is None:
                raw = b""
            elif isinstance(arg, (bytes, bytearray)):
                raw = bytes(arg)
            elif isinstance(arg, str):
                try:
                    raw = arg.encode("latin-1")
                except UnicodeEncodeError:
                    raw = arg.encode("utf-8")
            else:
                raw = b""
            return {"op": op, "value": base64.b64encode(raw).decode("ascii")}

        if t_type == Transform.MASK:
            key_hex = ""
            if arg:
                try:
                    byte = arg[0] if isinstance(arg, (bytes, bytearray)) else arg
                    key_hex = MalleableUtil.to_hex(byte) or ""
                except (TypeError, ValueError, IndexError):
                    key_hex = ""
            return {"op": op, "key": key_hex}

        return {"op": op}

    @staticmethod
    def _terminator_for_agent(terminator) -> dict:
        """Map a Terminator object to its agent-JSON representation.

        An unknown / NONE terminator falls back to ``{"type": "print"}`` so
        the agent always has a usable storage location.
        """
        t_type = getattr(terminator, "type", Terminator.PRINT)
        name = _TERMINATOR_TYPE_NAMES.get(t_type)
        if name is None:
            return {"type": "print"}

        if t_type in (Terminator.HEADER, Terminator.PARAMETER):
            arg = getattr(terminator, "arg", None) or ""
            return {"type": name, "arg": arg}

        return {"type": name}

    def ingest(self, file: str = None, content: str = None):
        """Ingest a profile file into the Profile object.

        Args:
            file (str): Filename to be read and parsed.
        """
        # if not file or not os.path.isfile(file):
        #    MalleableError.throw(self.__class__, "ingest", "Invalid file: %s" % str(file))

        if file:
            with open(file) as f:
                content = f.read()
            if not content:
                MalleableError.throw(
                    self.__class__, "ingest", "Empty file: %s" % str(file)
                )

        self._parse(self._pattern().search_string(content))
