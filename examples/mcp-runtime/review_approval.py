"""Separate terminal review. Token is read without echo, never via argv."""

import getpass
import os
import sys

from agentproof.approval import ApprovalStore
from agentproof.auth import OAuthIntrospector


def setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing host configuration: {name}")
    return value


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python review_approval.py REQUEST_ID")
    approvals = ApprovalStore(setting("AGENTPROOF_APPROVAL_DB"))
    try:
        request = approvals.get(sys.argv[1])
        for key in ("id", "subject", "tool", "arguments", "policy_digest", "expires_at", "state"):
            print(f"{key}: {request[key]}")
        if request["state"] != "pending":
            raise SystemExit("request is not pending")
        approve = input("Approve this exact operation? Type APPROVE: ") == "APPROVE"
        token = getpass.getpass("Reviewer OAuth access token: ")
        introspector = OAuthIntrospector(setting("AGENTPROOF_INTROSPECT_URL"),
                                         setting("AGENTPROOF_CLIENT_ID"), setting("AGENTPROOF_CLIENT_SECRET"),
                                         setting("AGENTPROOF_ISSUER"), setting("AGENTPROOF_REVIEWER_AUDIENCE"))
        reviewer = introspector.verify(token)
        approvals.review(request["id"], reviewer, approve)
        print("Approved once" if approve else "Denied")
    finally:
        approvals.close()


if __name__ == "__main__":
    main()
