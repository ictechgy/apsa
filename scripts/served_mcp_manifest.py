"""Validate actual stdio tools/list against the proposed, unapproved contract."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import tempfile
from pathlib import Path


async def capture(root: Path, contract: Path) -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from mobile_audit.mcp_server import manifest_sha256

    expected = json.loads(contract.read_text())
    result = {"published_baseline_approved": False, "transport": "actual-stdio-tools/list"}
    with tempfile.TemporaryDirectory(prefix="apsa-served-mcp-") as directory:
        workspace = Path(directory)
        for variant, runtime in (("default", False), ("runtime", True)):
            scope = workspace / variant
            scope.mkdir()
            home = workspace / (variant + "-home")
            argv = ["-I", "-m", "apsa", "--home", str(home), "mcp", "--root", str(scope)]
            if runtime:
                argv.append("--allow-runtime")
            async with stdio_client(StdioServerParameters(command=sys.executable, args=argv)) as streams:
                async with ClientSession(*streams) as session:
                    initialized = await session.initialize()
                    listed = await session.list_tools()
                    # Preserve full SDK response objects separately from canonical
                    # hash input. These are actual served observations, not templates.
                    (root / (variant + "-initialize.json")).write_text(
                        initialized.model_dump_json(by_alias=True, indent=2) + "\n"
                    )
                    (root / (variant + "-tools-list.json")).write_text(
                        listed.model_dump_json(by_alias=True, indent=2) + "\n"
                    )
                    tools = listed.tools
                    served = [tool.model_dump(by_alias=True, exclude_none=True) for tool in tools]
                    digest = manifest_sha256(served)
                    template = [
                        "<python>",
                        "-I",
                        "-m",
                        "apsa",
                        "--home",
                        "<scratch>/" + variant + "-home",
                        "mcp",
                        "--root",
                        "<scratch>/" + variant,
                    ]
                    if runtime:
                        template.append("--allow-runtime")
                    result[variant] = {
                        "sha256": digest,
                        "tools": served,
                        "argv": template,
                        "argv_sha256": hashlib.sha256(
                            json.dumps(template, separators=(",", ":")).encode()
                        ).hexdigest(),
                        "argv_scope": "canonical-template; interpreter and fresh scratch paths substituted at invocation",
                        "contract_matched": digest == expected[variant]["sha256"],
                        "initialize_response": variant + "-initialize.json",
                        "list_tools_response": variant + "-tools-list.json",
                    }
                    (root / "served-observation.json").write_text(json.dumps(result, indent=2) + "\n")
                    if digest != expected[variant]["sha256"]:
                        raise ValueError(
                            "Actual served manifest differs from the proposed " + variant + " contract"
                        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    try:
        result = asyncio.run(asyncio.wait_for(capture(args.out, args.contract), timeout=90))
    except Exception as error:
        (args.out / "failure.json").write_text(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "published_baseline_approved": False,
                    "completed_scope_responses": [
                        name
                        for name in ("default-tools-list.json", "runtime-tools-list.json")
                        if (args.out / name).is_file()
                    ],
                },
                indent=2,
            )
            + "\n"
        )
        raise
    print(json.dumps({variant: result[variant]["sha256"] for variant in ("default", "runtime")}))


if __name__ == "__main__":
    main()
