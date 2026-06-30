#!/usr/bin/env python3
"""Static policy checks for rendered bot configuration."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


ALLOWED_TOP_LEVEL = {
    "state_file",
    "self_person_id",
    "server",
    "webex",
    "codex",
    "rooms",
}
MIKU_SELF_PERSON_ID = "Y2lzY29zcGFyazovL3VzL1BFT1BMRS9iYTcyOTQzZi1jNjdlLTRlNjUtOGYyYi01MGQwNmJlNGM0MzQ"
READ_ONLY_SOURCE_ROOM_PINS = {
    (
        "Y2lzY29zcGFyazovL3VzL1JPT00vZjY2Yzg5MDAtYzdiYi0xMWU4LTk2NmQtYzU3YTQxMzQxYjI4"
    ): {
        "output_room_id": "Y2lzY29zcGFyazovL3VzL1JPT00vNTMxMzQ4ZjAtNmJlZC0xMWYxLWFhNWUtZGY0YjBjYzc4YzY5",
        "trigger": "always",
        "prefixes": ["@miku.gen"],
        "allowed_person_emails": ["wmejenkin@sparkbot.io"],
    },
}
JENKINS_ROOM_PINS = {
    (
        "Y2lzY29zcGFyazovL3VzL1JPT00vZjY2Yzg5MDAtYzdiYi0xMWU4LTk2NmQtYzU3YTQxMzQxYjI4"
    ): {
        "trigger": "always",
        "prefixes": ["@miku.gen"],
        "allowed_person_emails": ["wmejenkin@sparkbot.io"],
        "allowed_person_ids": [],
    },
    (
        "Y2lzY29zcGFyazovL3VzL1JPT00vNTMxMzQ4ZjAtNmJlZC0xMWYxLWFhNWUtZGY0YjBjYzc4YzY5"
    ): {
        "trigger": "prefix",
        "prefixes": ["wme jenkins"],
        "allowed_person_emails": [
            "hoteng@cisco.com",
            "wmejenkin@sparkbot.io",
            "webex-generic-account-E2E-tester@webex.bot",
        ],
        "allowed_person_ids": [],
    },
}
JENKINS_FOLLOWUP_PINS = {
    (
        "Y2lzY29zcGFyazovL3VzL1JPT00vZjY2Yzg5MDAtYzdiYi0xMWU4LTk2NmQtYzU3YTQxMzQxYjI4"
    ): {
        "enabled": True,
        "triggers": ["mention", "quoted-bot-reply"],
        "allowed_person_emails": [
            "hoteng@cisco.com",
            "webex-generic-account-E2E-tester@webex.bot",
        ],
        "allowed_person_ids": [],
        "reply_format": "jenkins-followup-json",
    },
}
JENKINS_FOLLOWUP_FORBIDDEN_ROOM_IDS = {
    "Y2lzY29zcGFyazovL3VzL1JPT00vNTMxMzQ4ZjAtNmJlZC0xMWYxLWFhNWUtZGY0YjBjYzc4YzY5",
}
GENERIC_ROOM_PINS = {
    (
        "Y2lzY29zcGFyazovL3VzL1JPT00vNjI1MzcwNzAtNmJjOS0xMWYxLWFiMGEtMDUxM2Y2OGNiOGM0"
    ): {
        "name": "miku bot test",
        "trigger": "prefix",
        "prefixes": ["/codex"],
        "allowed_person_emails": ["webex-generic-account-E2E-tester@webex.bot"],
        "allowed_person_ids": [],
        "prompt_template": """
You are Codex running from the miku Webex generic-account bot.

Reply concisely in Simplified Chinese unless the user asks otherwise.

Room: {room_id}
Message ID: {message_id}
Sender: {person_email}

User message:
{body}
""",
    },
}
JENKINS_CODEX_PINS = {
    "model": "gpt-5.5",
    "model_reasoning_effort": "xhigh",
}
JENKINS_STAGING_SOURCE_ROOM_ID = (
    "Y2lzY29zcGFyazovL3VzL1JPT00vZjY2Yzg5MDAtYzdiYi0xMWU4LTk2NmQtYzU3YTQxMzQxYjI4"
)
JENKINS_DIAGNOSIS_PROMPT_HASHES = {
    "Y2lzY29zcGFyazovL3VzL1JPT00vNTMxMzQ4ZjAtNmJlZC0xMWYxLWFhNWUtZGY0YjBjYzc4YzY5": (
        "331f872ee321192a3003bf0b4186d9ef92c9ae5d1901f2947530276ef11257d6"
    ),
    JENKINS_STAGING_SOURCE_ROOM_ID: (
        "e4bb91bd2faaabcaba7231cb6a2a072697317dfa7825f4a1d21db287f1d369e1"
    ),
}
JENKINS_FOLLOWUP_PROMPT_HASHES = {
    JENKINS_STAGING_SOURCE_ROOM_ID: (
        "310d7101ec50c81c7dc9f6481ee077095e12aba827a3783d398099189769a153"
    ),
}
ALLOWED_SERVER_KEYS = {
    "bind",
    "event_path",
    "health_path",
    "sidecar_token_env",
    "allow_unauthenticated",
    "max_concurrent_requests",
    "attempt_lease_secs",
}
ALLOWED_WEBEX_KEYS = {
    "access_token_env",
    "access_token_file_env",
    "access_token_file",
}
ALLOWED_CODEX_KEYS = {
    "bin",
    "cwd",
    "codex_home",
    "profile",
    "model",
    "model_reasoning_effort",
    "sandbox",
    "approval_policy",
    "timeout_secs",
    "output_limit_chars",
    "skip_git_repo_check",
    "ephemeral",
    "isolation",
}
ALLOWED_ISOLATION_KEYS = {
    "mode",
    "trusted_prompt_authors",
}
ALLOWED_ROOM_KEYS = {
    "name",
    "room_id",
    "output_room_id",
    "forward_source_message",
    "read_only_source",
    "jenkins_context",
    "followup",
    "reply_format",
    "trigger",
    "prefixes",
    "allow_all_senders",
    "allowed_person_ids",
    "allowed_person_emails",
    "prompt_template",
    "codex",
}
ALLOWED_FOLLOWUP_KEYS = {
    "enabled",
    "triggers",
    "allow_all_senders",
    "allowed_person_ids",
    "allowed_person_emails",
    "max_thread_messages",
    "max_thread_context_chars",
    "reply_format",
    "prompt_template",
}
ALLOWED_JENKINS_CONTEXT_KEYS = {
    "enabled",
    "node_bin",
    "script",
    "env_file",
    "timeout_secs",
    "max_urls",
    "output_limit_chars",
}
ALLOWED_REPLY_FORMATS = {
    "markdown",
    "jenkins-diagnosis-json",
    "jenkins-followup-json",
}
JENKINS_CONTEXT_REPLY_FORMATS = {
    "jenkins-diagnosis-json",
    "jenkins-followup-json",
}
ALLOWED_TRIGGERS = {
    "mention",
    "prefix",
    "always",
    "never",
}
ALLOWED_FOLLOWUP_TRIGGERS = {
    "mention",
    "quoted-bot-reply",
}
ALLOWED_JENKINS_HELPERS = {
    "/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs",
}
DISALLOWED_SECRET_KEYS = {
    "access_token",
    "refresh_token",
    "client_secret",
    "bot_token",
    "password",
}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


class Validator:
    def __init__(
        self,
        document: dict[str, Any],
        *,
        require_ephemeral_linux_user: bool = False,
        require_current_user: bool = False,
    ) -> None:
        self.document = document
        self.require_ephemeral_linux_user = require_ephemeral_linux_user
        self.require_current_user = require_current_user
        self.errors: list[str] = []

    def validate(self) -> list[str]:
        self.expect_keys(self.document, "config", ALLOWED_TOP_LEVEL)
        self.reject_secret_material(self.document, "config")
        self.validate_server(as_table(self.document.get("server"), "server", self.errors))
        self.validate_webex(as_table(self.document.get("webex"), "webex", self.errors))
        self.require_equal(self.document, "config", "self_person_id", MIKU_SELF_PERSON_ID)
        self.validate_codex(
            as_table(self.document.get("codex"), "codex", self.errors),
            "codex",
            allow_profile=False,
            require_fixed=True,
            require_ephemeral_linux_user=self.require_ephemeral_linux_user,
            require_current_user=self.require_current_user,
        )
        self.validate_top_level_paths()
        self.validate_rooms(self.document.get("rooms"))
        return self.errors

    def validate_server(self, server: dict[str, Any]) -> None:
        self.expect_keys(server, "server", ALLOWED_SERVER_KEYS)
        self.require_equal(server, "server", "bind", "127.0.0.1:8787")
        self.require_equal(server, "server", "event_path", "/webex/events")
        self.require_equal(server, "server", "health_path", "/healthz")
        self.require_equal(server, "server", "sidecar_token_env", "WEBEX_SIDECAR_TOKEN")
        self.require_equal(server, "server", "allow_unauthenticated", False)
        max_concurrent_requests = 4 if self.require_ephemeral_linux_user else 8
        self.expect_int_range(
            server,
            "server",
            "max_concurrent_requests",
            1,
            max_concurrent_requests,
            required=True,
        )
        self.require_equal(server, "server", "attempt_lease_secs", 3600)

    def validate_webex(self, webex: dict[str, Any]) -> None:
        self.expect_keys(webex, "webex", ALLOWED_WEBEX_KEYS)
        self.require_equal(
            webex,
            "webex",
            "access_token_file",
            "/var/lib/webex-headless-access/access-token",
        )
        if "access_token_env" in webex:
            self.expect_equal(webex, "webex", "access_token_env", "WEBEX_ACCESS_TOKEN")
        if "access_token_file_env" in webex:
            self.expect_equal(webex, "webex", "access_token_file_env", "WEBEX_ACCESS_TOKEN_FILE")

    def validate_codex(
        self,
        codex: dict[str, Any],
        path: str,
        *,
        allow_profile: bool,
        require_fixed: bool,
        require_ephemeral_linux_user: bool,
        require_current_user: bool,
    ) -> None:
        self.expect_keys(codex, path, ALLOWED_CODEX_KEYS)
        self.expect_or_require_equal(codex, path, "bin", "codex", require_fixed)
        self.expect_or_require_equal(
            codex,
            path,
            "cwd",
            "/var/lib/webex-generic-account-bot/codex-workspace",
            require_fixed,
        )
        self.expect_or_require_equal(
            codex,
            path,
            "codex_home",
            "/var/lib/webex-generic-account-bot/codex-home",
            require_fixed,
        )
        self.expect_or_require_equal(codex, path, "model", "gpt-5.5", require_fixed)
        if "profile" in codex and not allow_profile:
            self.error(f"{path}.profile is deployment-host policy and must not be set here")
        if "model_reasoning_effort" in codex:
            self.expect_enum(
                codex,
                path,
                "model_reasoning_effort",
                {"minimal", "low", "medium", "high", "xhigh"},
            )
        self.expect_or_require_equal(
            codex,
            path,
            "model_reasoning_effort",
            "xhigh",
            require_fixed,
        )
        self.expect_or_require_equal(codex, path, "sandbox", "read-only", require_fixed)
        self.expect_or_require_equal(codex, path, "approval_policy", "never", require_fixed)
        self.expect_int_range(codex, path, "timeout_secs", 1, 1200, required=require_fixed)
        self.expect_int_range(
            codex,
            path,
            "output_limit_chars",
            1,
            20_000,
            required=require_fixed,
        )
        self.expect_or_require_equal(codex, path, "skip_git_repo_check", True, require_fixed)
        self.expect_or_require_equal(codex, path, "ephemeral", True, require_fixed)
        if require_fixed or "isolation" in codex:
            self.validate_isolation(
                as_table(codex.get("isolation"), f"{path}.isolation", self.errors),
                f"{path}.isolation",
                require_fixed=True,
                require_ephemeral_linux_user=require_ephemeral_linux_user,
                require_current_user=require_current_user,
            )

    def validate_isolation(
        self,
        isolation: dict[str, Any],
        path: str,
        *,
        require_fixed: bool,
        require_ephemeral_linux_user: bool,
        require_current_user: bool,
    ) -> None:
        self.expect_keys(isolation, path, ALLOWED_ISOLATION_KEYS)
        if require_ephemeral_linux_user:
            self.expect_or_require_equal(
                isolation,
                path,
                "mode",
                "ephemeral-linux-user",
                require_fixed,
            )
            self.expect_or_require_equal(
                isolation,
                path,
                "trusted_prompt_authors",
                False,
                require_fixed,
            )
            return
        if require_current_user:
            self.expect_or_require_equal(
                isolation,
                path,
                "mode",
                "current-user",
                require_fixed,
            )
            self.expect_or_require_equal(
                isolation,
                path,
                "trusted_prompt_authors",
                True,
                require_fixed,
            )
            return

        mode = isolation.get("mode")
        if mode is None:
            if require_fixed:
                self.error(
                    f"{path}.mode is required and must be one of "
                    "'current-user', 'ephemeral-linux-user'"
                )
        else:
            self.expect_enum(
                isolation,
                path,
                "mode",
                {"current-user", "ephemeral-linux-user"},
            )

        trusted_prompt_authors = isolation.get("trusted_prompt_authors")
        if trusted_prompt_authors is None:
            if require_fixed:
                self.error(f"{path}.trusted_prompt_authors is required and must be true or false")
            return
        if not isinstance(trusted_prompt_authors, bool):
            self.error(f"{path}.trusted_prompt_authors must be true or false")
            return
        if mode == "current-user" and not trusted_prompt_authors:
            self.error(f"{path}.trusted_prompt_authors must be true for current-user mode")
        elif mode == "ephemeral-linux-user" and trusted_prompt_authors:
            self.error(
                f"{path}.trusted_prompt_authors must be false for ephemeral-linux-user mode"
            )

    def validate_top_level_paths(self) -> None:
        state_file = self.document.get("state_file")
        if state_file is None:
            self.error("state_file is required and must be under /var/lib/webex-generic-account-bot/state/")
            return
        self.expect_path_prefix(
            state_file,
            "state_file",
            "/var/lib/webex-generic-account-bot/state/",
        )

    def validate_rooms(self, rooms: Any) -> None:
        if not isinstance(rooms, list) or not rooms:
            self.error("rooms must contain at least one [[rooms]] entry")
            return
        rooms_by_id = {
            room.get("room_id"): room
            for room in rooms
            if isinstance(room, dict) and isinstance(room.get("room_id"), str)
        }
        self.require_known_jenkins_rooms(rooms_by_id)
        allowed_room_ids = set(JENKINS_ROOM_PINS) | set(GENERIC_ROOM_PINS)
        for room_id in sorted(set(rooms_by_id) - allowed_room_ids):
            self.error(f"room_id is not allowlisted by host policy: {room_id}")
        all_room_ids = set(rooms_by_id)
        seen_room_ids: set[str] = set()
        for index, raw_room in enumerate(rooms):
            path = f"rooms[{index}]"
            room = as_table(raw_room, path, self.errors)
            self.expect_keys(room, path, ALLOWED_ROOM_KEYS)
            room_id = room.get("room_id")
            if not isinstance(room_id, str) or not room_id.strip():
                self.error(f"{path}.room_id must be a non-empty string")
            elif room_id in seen_room_ids:
                self.error(f"{path}.room_id duplicates {room_id}")
            else:
                seen_room_ids.add(room_id)
            output_room_id = room.get("output_room_id")
            read_only_source_pins = READ_ONLY_SOURCE_ROOM_PINS.get(room_id)
            jenkins_room_pins = JENKINS_ROOM_PINS.get(room_id)
            jenkins_followup_pins = JENKINS_FOLLOWUP_PINS.get(room_id)
            generic_room_pins = GENERIC_ROOM_PINS.get(room_id)
            if "forward_source_message" in room and not isinstance(room["forward_source_message"], bool):
                self.error(f"{path}.forward_source_message must be true or false")
            if "read_only_source" in room and not isinstance(room["read_only_source"], bool):
                self.error(f"{path}.read_only_source must be true or false")
            if read_only_source_pins is not None:
                self.require_equal(room, path, "forward_source_message", True)
                self.require_equal(room, path, "read_only_source", True)
                for key, expected in read_only_source_pins.items():
                    self.require_equal(room, path, key, expected)
            elif room.get("read_only_source") is True:
                self.error(f"{path}.room_id is not an allowed read-only source room")
            if output_room_id is not None:
                if not isinstance(output_room_id, str) or not output_room_id.strip():
                    self.error(f"{path}.output_room_id must be a non-empty string when set")
                elif output_room_id == room_id:
                    self.error(f"{path}.output_room_id must differ from room_id")
                elif output_room_id not in all_room_ids:
                    self.error(f"{path}.output_room_id must reference a declared room_id")
                elif rooms_by_id.get(output_room_id, {}).get("read_only_source") is True:
                    self.error(f"{path}.output_room_id must not reference a read-only source room")
                self.require_equal(room, path, "forward_source_message", True)
                self.require_equal(room, path, "read_only_source", True)
            if room.get("forward_source_message") is True and output_room_id is None:
                self.error(f"{path}.forward_source_message requires output_room_id")
            if room.get("read_only_source") is True and output_room_id is None:
                self.error(f"{path}.read_only_source requires output_room_id")
            self.expect_equal(room, path, "allow_all_senders", False)
            self.require_sender_allowlist(room, path)
            if "reply_format" in room:
                self.expect_enum(room, path, "reply_format", ALLOWED_REPLY_FORMATS)
            jenkins_context_required = is_jenkins_reply_format(room.get("reply_format"))
            if jenkins_context_required and jenkins_room_pins is None:
                self.error(f"{path}.reply_format is only allowed for known Jenkins rooms")
            if jenkins_room_pins is not None:
                self.require_equal(room, path, "reply_format", "jenkins-diagnosis-json")
                for key, expected in jenkins_room_pins.items():
                    if key == "allowed_person_ids":
                        self.expect_equal(room, path, key, expected)
                    else:
                        self.require_equal(room, path, key, expected)
                jenkins_context_required = True
            self.require_enum(room, path, "trigger", ALLOWED_TRIGGERS)
            self.expect_string_list(room, path, "prefixes", allow_empty=True)
            if room.get("trigger") == "prefix" and not non_empty_string_list(room.get("prefixes", [])):
                self.error(f"{path}.prefixes must not be empty when trigger is 'prefix'")
            if "allowed_person_ids" in room:
                self.expect_string_list(room, path, "allowed_person_ids", allow_empty=True)
            if "allowed_person_emails" in room:
                self.expect_string_list(room, path, "allowed_person_emails", allow_empty=True)
            if "prompt_template" in room and not non_empty_text(room["prompt_template"]):
                self.error(f"{path}.prompt_template must be a non-empty string")
            if generic_room_pins is not None:
                for key, expected in generic_room_pins.items():
                    if key == "prompt_template":
                        self.require_prompt_equal(room.get(key), f"{path}.{key}", expected)
                    elif key == "allowed_person_ids":
                        self.expect_equal(room, path, key, expected)
                    else:
                        self.require_equal(room, path, key, expected)
                for forbidden_key in (
                    "output_room_id",
                    "forward_source_message",
                    "read_only_source",
                    "jenkins_context",
                    "followup",
                    "reply_format",
                    "codex",
                ):
                    if forbidden_key in room:
                        self.error(f"{path}.{forbidden_key} is not allowed for this pinned room")
            if jenkins_room_pins is not None:
                self.require_prompt_hash(
                    room.get("prompt_template"),
                    f"{path}.prompt_template",
                    JENKINS_DIAGNOSIS_PROMPT_HASHES[room_id],
                )
            if "codex" in room:
                self.validate_codex(
                    as_table(room["codex"], f"{path}.codex", self.errors),
                    f"{path}.codex",
                    allow_profile=False,
                    require_fixed=False,
                    require_ephemeral_linux_user=self.require_ephemeral_linux_user,
                    require_current_user=self.require_current_user,
                )
            if jenkins_room_pins is not None:
                codex = as_table(room.get("codex"), f"{path}.codex", self.errors)
                for key, expected in JENKINS_CODEX_PINS.items():
                    self.require_equal(codex, f"{path}.codex", key, expected)
            if "followup" in room:
                if room_id in JENKINS_FOLLOWUP_FORBIDDEN_ROOM_IDS:
                    self.error(f"{path}.followup is not allowed for this Jenkins room")
                followup = as_table(room["followup"], f"{path}.followup", self.errors)
                self.validate_followup(followup, f"{path}.followup")
                if jenkins_followup_pins is not None:
                    for key, expected in jenkins_followup_pins.items():
                        if key == "allowed_person_ids":
                            self.expect_equal(followup, f"{path}.followup", key, expected)
                        else:
                            self.require_equal(followup, f"{path}.followup", key, expected)
                    self.require_prompt_hash(
                        followup.get("prompt_template"),
                        f"{path}.followup.prompt_template",
                        JENKINS_FOLLOWUP_PROMPT_HASHES[room_id],
                    )
                if is_jenkins_reply_format(followup.get("reply_format")):
                    jenkins_context_required = True
                    if jenkins_room_pins is None:
                        self.error(f"{path}.followup.reply_format is only allowed for known Jenkins rooms")
            elif jenkins_followup_pins is not None:
                self.error(f"{path}.followup is required for known Jenkins follow-up rooms")
            if jenkins_context_required and "jenkins_context" not in room:
                self.error(f"{path}.jenkins_context is required for Jenkins reply formats")
            if "jenkins_context" in room:
                if jenkins_room_pins is None:
                    self.error(f"{path}.jenkins_context is only allowed for known Jenkins rooms")
                self.require_equal(room, path, "reply_format", "jenkins-diagnosis-json")
                if isinstance(room.get("followup"), dict) and room["followup"].get("enabled") is True:
                    self.require_equal(
                        room["followup"],
                        f"{path}.followup",
                        "reply_format",
                        "jenkins-followup-json",
                    )
                self.validate_jenkins_context(
                    as_table(room["jenkins_context"], f"{path}.jenkins_context", self.errors),
                    f"{path}.jenkins_context",
                    require_enabled=jenkins_context_required,
                )

    def require_known_jenkins_rooms(self, rooms_by_id: dict[str, dict[str, Any]]) -> None:
        required_room_ids = set(READ_ONLY_SOURCE_ROOM_PINS) | set(JENKINS_ROOM_PINS)
        for room_id in sorted(required_room_ids - set(rooms_by_id)):
            self.error(f"required Jenkins room is missing: {room_id}")
        for room_id in sorted(set(JENKINS_FOLLOWUP_PINS) - set(rooms_by_id)):
            self.error(f"required Jenkins follow-up room is missing: {room_id}")

    def validate_followup(self, followup: dict[str, Any], path: str) -> None:
        self.expect_keys(followup, path, ALLOWED_FOLLOWUP_KEYS)
        enabled = followup.get("enabled", False)
        if "enabled" in followup and not isinstance(enabled, bool):
            self.error(f"{path}.enabled must be true or false")
        if enabled is True and "triggers" not in followup:
            self.error(f"{path}.triggers is required when enabled = true")
        triggers_valid = self.expect_string_list(
            followup,
            path,
            "triggers",
            allow_empty=enabled is not True,
        )
        if triggers_valid:
            for trigger in followup.get("triggers", []):
                if trigger not in ALLOWED_FOLLOWUP_TRIGGERS:
                    self.error(f"{path}.triggers contains unsupported trigger {trigger!r}")
        if enabled is True:
            self.expect_equal(followup, path, "allow_all_senders", False)
            self.require_sender_allowlist(followup, path)
        if "reply_format" in followup:
            self.expect_enum(followup, path, "reply_format", ALLOWED_REPLY_FORMATS)
        if "allowed_person_ids" in followup:
            self.expect_string_list(followup, path, "allowed_person_ids", allow_empty=True)
        if "allowed_person_emails" in followup:
            self.expect_string_list(followup, path, "allowed_person_emails", allow_empty=True)
        self.expect_int_range(followup, path, "max_thread_messages", 1, 500)
        self.expect_int_range(followup, path, "max_thread_context_chars", 1, 50_000)
        if "prompt_template" in followup and not non_empty_text(followup["prompt_template"]):
            self.error(f"{path}.prompt_template must be a non-empty string")

    def validate_jenkins_context(
        self,
        context: dict[str, Any],
        path: str,
        *,
        require_enabled: bool,
    ) -> None:
        self.expect_keys(context, path, ALLOWED_JENKINS_CONTEXT_KEYS)
        enabled = context.get("enabled", True)
        if "enabled" in context and not isinstance(enabled, bool):
            self.error(f"{path}.enabled must be true or false")
        self.expect_equal(context, path, "node_bin", "/usr/bin/node")
        self.expect_enum(context, path, "script", ALLOWED_JENKINS_HELPERS)
        self.expect_equal(context, path, "env_file", "/etc/webex-generic-account-bot/jenkins.env")
        self.expect_int_range(context, path, "timeout_secs", 1, 600)
        self.expect_int_range(context, path, "max_urls", 1, 10)
        self.expect_int_range(context, path, "output_limit_chars", 1, 20_000)
        if enabled is False:
            if require_enabled:
                self.error(f"{path}.enabled must not be false for Jenkins reply formats")
            return
        self.require_equal(context, path, "node_bin", "/usr/bin/node")
        self.require_enum(context, path, "script", ALLOWED_JENKINS_HELPERS)
        self.require_equal(context, path, "env_file", "/etc/webex-generic-account-bot/jenkins.env")
        self.require_equal(context, path, "timeout_secs", 600)
        self.require_equal(context, path, "max_urls", 3)
        self.require_equal(context, path, "output_limit_chars", 5000)

    def reject_secret_material(self, value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key in DISALLOWED_SECRET_KEYS:
                    self.error(f"{child_path} must not be committed to config")
                self.reject_secret_material(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self.reject_secret_material(child, f"{path}[{index}]")
        elif isinstance(value, str) and PRIVATE_KEY_RE.search(value):
            self.error(f"{path} contains private key material")

    def require_sender_allowlist(self, table: dict[str, Any], path: str) -> None:
        person_ids = table.get("allowed_person_ids", [])
        emails = table.get("allowed_person_emails", [])
        if not non_empty_string_list(person_ids) and not non_empty_string_list(emails):
            self.error(f"{path} must configure allowed_person_ids or allowed_person_emails")

    def expect_keys(self, table: dict[str, Any], path: str, allowed: set[str]) -> None:
        for key in sorted(set(table) - allowed):
            self.error(f"{path}.{key} is not an allowed production config field")

    def expect_equal(self, table: dict[str, Any], path: str, key: str, expected: Any) -> None:
        if key not in table:
            return
        value = table[key]
        if isinstance(expected, bool) and not isinstance(value, bool):
            self.error(f"{path}.{key} must be {expected!r}")
            return
        if value != expected:
            self.error(f"{path}.{key} must be {expected!r}")

    def require_equal(self, table: dict[str, Any], path: str, key: str, expected: Any) -> None:
        if key not in table:
            self.error(f"{path}.{key} is required and must be {expected!r}")
            return
        self.expect_equal(table, path, key, expected)

    def require_prompt_hash(self, value: Any, path: str, expected_hash: str) -> None:
        if not isinstance(value, str):
            self.error(f"{path} must be a string")
            return
        normalised_value = normalise_prompt_text(value)
        actual_hash = hashlib.sha256(normalised_value.encode("utf-8")).hexdigest()
        if actual_hash != expected_hash:
            self.error(f"{path} must match the host-pinned prompt template")

    def require_prompt_equal(self, value: Any, path: str, expected: str) -> None:
        if not isinstance(value, str):
            self.error(f"{path} must be a string")
            return
        if normalise_prompt_text(value) != normalise_prompt_text(expected):
            self.error(f"{path} must match the host-pinned prompt template")

    def expect_or_require_equal(
        self,
        table: dict[str, Any],
        path: str,
        key: str,
        expected: Any,
        required: bool,
    ) -> None:
        if required:
            self.require_equal(table, path, key, expected)
        else:
            self.expect_equal(table, path, key, expected)

    def expect_enum(self, table: dict[str, Any], path: str, key: str, allowed: set[str]) -> None:
        value = table.get(key)
        if value is None:
            return
        if not isinstance(value, str):
            self.error(f"{path}.{key} must be a string")
            return
        if value not in allowed:
            allowed_values = ", ".join(sorted(repr(item) for item in allowed))
            self.error(f"{path}.{key} must be one of {allowed_values}")

    def require_enum(self, table: dict[str, Any], path: str, key: str, allowed: set[str]) -> None:
        if key not in table:
            allowed_values = ", ".join(sorted(repr(item) for item in allowed))
            self.error(f"{path}.{key} is required and must be one of {allowed_values}")
            return
        self.expect_enum(table, path, key, allowed)

    def expect_int_range(
        self,
        table: dict[str, Any],
        path: str,
        key: str,
        minimum: int,
        maximum: int,
        *,
        required: bool = False,
    ) -> None:
        if key not in table:
            if required:
                self.error(f"{path}.{key} is required and must be an integer from {minimum} to {maximum}")
            return
        value = table[key]
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            self.error(f"{path}.{key} must be an integer from {minimum} to {maximum}")

    def expect_string_list(
        self,
        table: dict[str, Any],
        path: str,
        key: str,
        *,
        allow_empty: bool,
    ) -> bool:
        if key not in table:
            return True
        value = table[key]
        if not isinstance(value, list) or any(not non_empty_string(item) for item in value):
            self.error(f"{path}.{key} must be a list of non-empty strings")
            return False
        elif not allow_empty and not value:
            self.error(f"{path}.{key} must not be empty")
            return False
        return True

    def expect_path_prefix(self, value: Any, path: str, expected_prefix: str) -> None:
        if not isinstance(value, str):
            self.error(f"{path} must be a string path")
            return
        candidate = PurePosixPath(value)
        prefix = PurePosixPath(expected_prefix)
        candidate_parts = candidate.parts
        prefix_parts = prefix.parts
        under_prefix = (
            len(candidate_parts) > len(prefix_parts)
            and candidate_parts[: len(prefix_parts)] == prefix_parts
        )
        if ".." in candidate_parts or not candidate.is_absolute() or not under_prefix:
            self.error(f"{path} must be under {expected_prefix}")

    def error(self, message: str) -> None:
        self.errors.append(message)


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() == value and bool(value)


def non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(non_empty_string(item) for item in value)


def is_jenkins_reply_format(value: Any) -> bool:
    return isinstance(value, str) and value in JENKINS_CONTEXT_REPLY_FORMATS


def normalise_prompt_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def as_table(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    errors.append(f"{path} must be a table")
    return {}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="static-config-check.py",
        usage=(
            "static-config-check.py [--require-ephemeral-linux-user | --require-current-user] "
            "<rendered-config.toml>"
        ),
        allow_abbrev=False,
    )
    isolation_requirement = parser.add_mutually_exclusive_group()
    isolation_requirement.add_argument("--require-ephemeral-linux-user", action="store_true")
    isolation_requirement.add_argument("--require-current-user", action="store_true")
    parser.add_argument("rendered_config")
    arguments = parser.parse_args(argv[1:])

    config_path = arguments.rendered_config
    if tomllib is None:
        print(
            "static config check requires Python 3.11+ tomllib or the tomli package",
            file=sys.stderr,
        )
        return 2

    try:
        with open(config_path, "rb") as config_file:
            document = tomllib.load(config_file)
    except tomllib.TOMLDecodeError as error:
        print(f"failed to parse {config_path}: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"failed to read {config_path}: {error}", file=sys.stderr)
        return 1

    errors = Validator(
        document,
        require_ephemeral_linux_user=arguments.require_ephemeral_linux_user,
        require_current_user=arguments.require_current_user,
    ).validate()
    if errors:
        for error in errors:
            print(f"static_config_error={error}", file=sys.stderr)
        return 1

    print("static_config_check=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
