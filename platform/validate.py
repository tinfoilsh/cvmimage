#!/usr/bin/env python3
"""Validate the machine inventory and platform security policies."""

import json
import re
import sys
from pathlib import Path

HEX_RE = re.compile(r"^[0-9a-f]+$")
VERSION_RE = re.compile(r"^\d+\.\d+$")

SEV_ID_LEN = 128
PPID_LEN = 32

SEV_FIELDS = {
    "minimum_build", "minimum_api_version", "minimum_abi_version",
    "minimum_guest_svn", "minimum_tcb", "minimum_launch_tcb",
    "guest_policy", "platform_info", "permit_provisional_firmware",
    "vmpl", "image_id", "family_id",
    "minimum_launch_mitigation_vector", "minimum_current_mitigation_vector",
}
TCB_FIELDS = {"bl_spl", "tee_spl", "snp_spl", "ucode_spl"}
# Turin (family 1Ah) TCBs carry a fifth component; absent on Genoa.
TCB_OPTIONAL_FIELDS = {"fmc_spl"}
GUEST_POLICY_FIELDS = {"debug", "smt", "migrate_ma", "single_socket"}
GUEST_POLICY_OPTIONAL_FIELDS = {
    "cxl_allowed", "mem_aes256_xts", "rapl_dis", "ciphertext_hiding_dram",
    "page_swap_disable",
}
PLATFORM_INFO_FIELDS = {
    "smt_enabled", "tsme_enabled", "ecc_enabled", "rapl_disabled",
    "ciphertext_hiding_dram",
}
PLATFORM_INFO_OPTIONAL_FIELDS = {
    "alias_check_complete", "iommu_write_safe", "tio_enabled",
}
TDX_FIELDS = {
    "qe_vendor_id", "minimum_tee_tcb_svn", "mr_seam", "td_attributes",
    "xfam", "minimum_tcb_evaluation_data_number",
}
errors: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def no_duplicates_hook(pairs):
    keys = [k for k, _ in pairs]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        err(f"duplicate JSON keys: {sorted(dupes)}")
    return dict(pairs)


def load(path: Path):
    try:
        return json.loads(path.read_text(), object_pairs_hook=no_duplicates_hook)
    except FileNotFoundError:
        err(f"{path}: missing")
    except json.JSONDecodeError as exc:
        err(f"{path}: invalid JSON: {exc}")
    return None


def check_members(context: str, block: dict, required: set, optional: set = frozenset()) -> None:
    missing = required - set(block)
    if missing:
        err(f"{context}: missing required members {sorted(missing)}")
    unknown = set(block) - required - optional
    if unknown:
        err(f"{context}: unknown members {sorted(unknown)}")


def check_hex(context: str, value, length: int) -> None:
    if not isinstance(value, str) or len(value) != length or not HEX_RE.match(value):
        err(f"{context}: expected {length} lowercase hex chars, got {value!r}")


def check_bools(context: str, block: dict) -> None:
    for k, v in block.items():
        if not isinstance(v, bool):
            err(f"{context}.{k}: must be a boolean, got {v!r}")


def check_uint(context: str, value) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        err(f"{context}: must be a non-negative integer, got {value!r}")


def validate_sev_policy(name: str, block: dict) -> None:
    ctx = f"policy {name}"
    check_members(f"{ctx}: sev_snp", block, SEV_FIELDS)
    for tcb_field in ("minimum_tcb", "minimum_launch_tcb"):
        tcb = block.get(tcb_field, {})
        check_members(f"{ctx}: {tcb_field}", tcb, TCB_FIELDS, TCB_OPTIONAL_FIELDS)
        for k, v in tcb.items():
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 255:
                err(f"{ctx}: {tcb_field}.{k} out of range: {v!r}")
    gp = block.get("guest_policy", {})
    check_members(f"{ctx}: guest_policy", gp, GUEST_POLICY_FIELDS, GUEST_POLICY_OPTIONAL_FIELDS)
    check_bools(f"{ctx}: guest_policy", gp)
    pi = block.get("platform_info", {})
    check_members(f"{ctx}: platform_info", pi, PLATFORM_INFO_FIELDS, PLATFORM_INFO_OPTIONAL_FIELDS)
    check_bools(f"{ctx}: platform_info", pi)
    for field in ("minimum_api_version", "minimum_abi_version"):
        if not VERSION_RE.match(str(block.get(field, ""))):
            err(f"{ctx}: {field} must be a 'maj.min' string")
    check_uint(f"{ctx}: minimum_build", block.get("minimum_build"))
    check_uint(f"{ctx}: minimum_guest_svn", block.get("minimum_guest_svn"))
    check_uint(f"{ctx}: minimum_launch_mitigation_vector",
               block.get("minimum_launch_mitigation_vector"))
    check_uint(f"{ctx}: minimum_current_mitigation_vector",
               block.get("minimum_current_mitigation_vector"))
    if not isinstance(block.get("permit_provisional_firmware"), bool):
        err(f"{ctx}: permit_provisional_firmware must be a boolean")
    vmpl = block.get("vmpl")
    if not isinstance(vmpl, int) or isinstance(vmpl, bool) or not 0 <= vmpl <= 3:
        err(f"{ctx}: vmpl must be an integer 0-3, got {vmpl!r}")
    check_hex(f"{ctx}: image_id", block.get("image_id"), 32)
    check_hex(f"{ctx}: family_id", block.get("family_id"), 32)


def validate_tdx_policy(name: str, block: dict) -> None:
    ctx = f"policy {name}"
    check_members(f"{ctx}: tdx", block, TDX_FIELDS)
    check_hex(f"{ctx}: qe_vendor_id", block.get("qe_vendor_id"), 32)
    check_hex(f"{ctx}: minimum_tee_tcb_svn", block.get("minimum_tee_tcb_svn"), 32)
    check_hex(f"{ctx}: mr_seam", block.get("mr_seam"), 96)
    check_hex(f"{ctx}: td_attributes", block.get("td_attributes"), 16)
    check_hex(f"{ctx}: xfam", block.get("xfam"), 16)
    check_uint(f"{ctx}: minimum_tcb_evaluation_data_number",
               block.get("minimum_tcb_evaluation_data_number"))


def main() -> int:
    errors.clear()
    root = Path(__file__).parent
    machines = load(root / "machines.json")
    policies = load(root / "policies.json")
    if not isinstance(machines, dict) or not isinstance(policies, dict) or not machines or not policies:
        err("machines and policies must be non-empty objects")
        print("\n".join(errors), file=sys.stderr)
        return 1

    for name, policy in policies.items():
        if not isinstance(policy, dict):
            err(f"policy {name}: must be an object")
            continue
        platform = policy.get("platform")
        if platform not in ("sev-snp", "tdx"):
            err(f"policy {name}: invalid platform {platform!r}")
            continue
        block_key = "sev_snp" if platform == "sev-snp" else "tdx"
        if set(policy) != {"platform", block_key}:
            err(f"policy {name}: must contain exactly 'platform' and '{block_key}'")
            continue
        if not isinstance(policy[block_key], dict):
            err(f"policy {name}: {block_key} must be an object")
            continue
        if platform == "sev-snp":
            validate_sev_policy(name, policy[block_key])
        else:
            validate_tdx_policy(name, policy[block_key])

    for identifier, policy_name in machines.items():
        if not isinstance(policy_name, str):
            err(f"machines[{identifier[:16]}...]: value must be a policy name string "
                "(no metadata objects allowed)")
            continue
        if policy_name not in policies:
            err(f"machines[{identifier[:16]}...]: unknown policy {policy_name!r}")
            continue
        platform = policies[policy_name].get("platform") if isinstance(policies[policy_name], dict) else None
        if not HEX_RE.match(identifier or ""):
            err(f"machines key {identifier!r}: not lowercase hex")
        elif platform == "sev-snp":
            if len(identifier) != SEV_ID_LEN:
                err(f"machines[{identifier[:16]}...]: sev-snp identifier must be "
                    f"{SEV_ID_LEN} hex chars (Turin: 16 hex + 112 zeros), got {len(identifier)}")
            elif identifier == "0" * SEV_ID_LEN:
                err("machines: all-zero sev-snp identifier")
        elif platform == "tdx":
            if len(identifier) != PPID_LEN:
                err(f"machines[{identifier[:16]}...]: tdx identifier must be "
                    f"{PPID_LEN} hex chars, got {len(identifier)}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        print(f"\nvalidation FAILED: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"validation OK: {len(machines)} machines, {len(policies)} policies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
