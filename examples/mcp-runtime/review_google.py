"""Approve one pending write after interactive Google account sign-in."""

import os
import sys

from agentproof.approval import ApprovalStore
from agentproof.google_identity import GoogleReviewerLogin


def setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing host configuration: {name}")
    return value


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python review_google.py --whoami | REQUEST_ID")
    discover = sys.argv[1] == "--whoami"
    allowed_sub = None if discover else setting("AGENTPROOF_GOOGLE_REVIEWER_SUB")
    login = GoogleReviewerLogin(setting("AGENTPROOF_GOOGLE_CLIENT_CONFIG"), allowed_sub)
    if discover:
        reviewer = login.login()
        print(f"Google reviewer subject (configure privately): {reviewer.subject.removeprefix('google:')}")
        return
    approvals = ApprovalStore(setting("AGENTPROOF_APPROVAL_DB"))
    try:
        request = approvals.get(sys.argv[1])
        for key in ("id", "subject", "tool", "arguments", "policy_digest", "expires_at", "state"):
            print(f"{key}: {request[key]}")
        if request["state"] != "pending":
            raise SystemExit("request is not pending")
        answer = input("Approve this exact operation? Type APPROVE: ")
        reviewer = login.login()
        approvals.review(request["id"], reviewer, answer == "APPROVE")
        print("Approved once" if answer == "APPROVE" else "Denied")
    finally:
        approvals.close()


if __name__ == "__main__":
    main()
