from __future__ import annotations

import shlex


class UnsupportedGitHubCommand(ValueError):
    pass


def parse_github_command(
    command: str, *, agent_id: str, actor_id: str, correlation_id: str
) -> dict:
    """Normalize a bounded gh/git command subset; never execute the command."""
    parts = shlex.split(command)
    if not parts:
        raise UnsupportedGitHubCommand("Empty command")
    action_type = ""
    repository = ""
    visibility = ""
    destination = "api.github.com"
    if parts[:3] == ["gh", "repo", "create"]:
        action_type = "github.repository.create"
        repository = next((part for part in parts[3:] if not part.startswith("-")), "")
        visibility = "public" if "--public" in parts else "private" if "--private" in parts else ""
    elif parts[:3] == ["gh", "repo", "edit"]:
        action_type = "github.repository.visibility_change"
        repository = next((part for part in parts[3:] if not part.startswith("-")), "")
        for index, part in enumerate(parts):
            if part == "--visibility" and index + 1 < len(parts):
                visibility = parts[index + 1]
    elif parts[:3] == ["gh", "release", "create"]:
        action_type = "github.release.create"
    elif parts[:3] == ["gh", "release", "upload"]:
        action_type = "github.release.upload"
        destination = "uploads.github.com"
    elif parts[:2] == ["gh", "api"]:
        action_type = "github.api.request"
    elif parts[:2] == ["gh", "pr"] and len(parts) > 2 and parts[2] == "create":
        action_type = "github.pull_request.create"
    elif parts[:2] == ["gh", "issue"] and len(parts) > 2 and parts[2] == "create":
        action_type = "github.issue.create"
    elif parts[:2] == ["git", "push"]:
        action_type = "git.push"
        destination = "github.com"
    else:
        raise UnsupportedGitHubCommand("Command is outside the verified GitHub mediation subset")
    return {
        "action_type": action_type,
        "agent_id": agent_id,
        "actor_id": actor_id,
        "repository": repository,
        "requested_visibility": visibility,
        "destination": destination,
        "artifact_hashes": [],
        "working_directory": "",
        "correlation_id": correlation_id,
    }
