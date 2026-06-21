from llvmlite import ir
import json
from datetime import datetime

# ─────────────────────────────────────────
# THE MODULE
# in real research this comes from RetroWrite or Remill
# they lift the old binary and give you IR like this
# here we build it manually to simulate that
# ─────────────────────────────────────────
module = ir.Module(name="old_binary_lifted")
int32 = ir.IntType(32)
int8p = ir.PointerType(ir.IntType(8))
void  = ir.VoidType()

# function 1 — safe
fn_add = ir.Function(module, ir.FunctionType(int32, [int32, int32]), name="add")
fn_add.args[0].name = "a"
fn_add.args[1].name = "b"
blk = fn_add.append_basic_block("entry")
bld = ir.IRBuilder(blk)
bld.ret(bld.add(fn_add.args[0], fn_add.args[1], "result"))

# function 2 — vulnerable
fn_strcpy = ir.Function(module, ir.FunctionType(void, [int8p, int8p]), name="unsafe_strcpy")
fn_strcpy.args[0].name = "dst"
fn_strcpy.args[1].name = "src"
ir.IRBuilder(fn_strcpy.append_basic_block("entry")).ret_void()

# function 3 — vulnerable
fn_memcpy = ir.Function(module, ir.FunctionType(void, [int8p, int8p, int32]), name="unsafe_memcpy")
fn_memcpy.args[0].name = "dst"
fn_memcpy.args[1].name = "src"
fn_memcpy.args[2].name = "size"
ir.IRBuilder(fn_memcpy.append_basic_block("entry")).ret_void()

# function 4 — safe
fn_safe = ir.Function(module, ir.FunctionType(void, [int8p, int32]), name="safe_read")
fn_safe.args[0].name = "buf"
fn_safe.args[1].name = "len"
ir.IRBuilder(fn_safe.append_basic_block("entry")).ret_void()


# ─────────────────────────────────────────
# DANGEROUS PATTERNS
# these are function names your scanner flags
# in real research this list comes from CVE databases
# and security research papers
# ─────────────────────────────────────────
DANGEROUS_NAMES = [
    "unsafe_strcpy",
    "unsafe_memcpy",
    "unsafe_gets",
    "unsafe_sprintf",
    "unsafe_scanf",
]


def scan_for_vulnerabilities(module):
    findings = []

    for function in module.functions:
        name = function.name
        args = list(function.args)

        # check 1 — known dangerous name
        if any(danger in name for danger in DANGEROUS_NAMES):
            findings.append({
                "function": name,
                "issue": "known dangerous function",
                "risk": "HIGH",
                "fix": "replace with bounds-checked version",
                "cwe": "CWE-120"
            })
            continue

        # check 2 — two pointer args, no size
        pointer_args = [a for a in args if isinstance(a.type, ir.PointerType)]
        non_pointer_args = [a for a in args if not isinstance(a.type, ir.PointerType)]

        if len(pointer_args) >= 2 and len(non_pointer_args) == 0:
            findings.append({
                "function": name,
                "issue": "two pointer args with no size parameter",
                "risk": "MEDIUM",
                "fix": "add size parameter and insert bounds check",
                "cwe": "CWE-131"
            })
            continue

    return findings


def generate_report(findings, output_file="vulnerability_report.json"):
    report = {
        "tool": "BinaryLens",
        "version": "0.1",
        "timestamp": datetime.now().isoformat(),
        "total_functions_scanned": len(list(module.functions)),
        "total_vulnerabilities": len(findings),
        "findings": findings,
        "next_step": "apply fix passes to IR then recompile to target architecture"
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    return report


# ─────────────────────────────────────────
# RUN THE PIPELINE
# ─────────────────────────────────────────

print("=" * 60)
print("BINARY LENS — vulnerability scanner")
print("=" * 60)

print("\n[1] lifted IR:")
print(module)

print("\n[2] running analysis pass...")
findings = scan_for_vulnerabilities(module)
print(f"    scanned {len(list(module.functions))} functions")
print(f"    found {len(findings)} vulnerabilities")

print("\n[3] findings:")
for i, f in enumerate(findings, 1):
    print(f"\n    [{i}] {f['function']}")
    print(f"        issue : {f['issue']}")
    print(f"        risk  : {f['risk']}")
    print(f"        fix   : {f['fix']}")
    print(f"        cwe   : {f['cwe']}")

report = generate_report(findings)

print("\n[4] report saved to vulnerability_report.json")
print("\n[5] next step: apply fix passes and recompile to ARM64")
print("=" * 60)