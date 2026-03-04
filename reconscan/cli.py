import argparse
import sys
from typing import List, Optional

from .core import ReconEngine, ReconConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconscan",
        description="Advanced Web & JavaScript Reconnaissance Tool (rule-based, no AI).",
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL/domain when crawling (e.g. https://example.com).",
    )

    parser.add_argument(
        "--js",
        dest="js_file",
        help="Analyze a single local JavaScript file.",
    )

    parser.add_argument(
        "--js-list",
        dest="js_list",
        help="Analyze a list of JavaScript URLs (one per line).",
    )

    parser.add_argument(
        "--paste",
        action="store_true",
        help="Read JavaScript from stdin and analyze.",
    )

    parser.add_argument(
        "--probe",
        action="store_true",
        help="Enable safe HTTP endpoint behavior probing (HEAD/GET).",
    )

    parser.add_argument(
        "--graph-format",
        choices=["json", "dot", "html"],
        default="json",
        help="API surface graph output format.",
    )

    parser.add_argument(
        "--report-format",
        choices=["json", "md", "html"],
        default="json",
        help="Recon report output format.",
    )

    parser.add_argument(
        "--output",
        help="Optional output file path. Defaults to stdout.",
    )

    return parser


def read_stdin() -> str:
    return sys.stdin.read()


def determine_mode(args: argparse.Namespace) -> str:
    if args.paste:
        return "paste"
    if args.js_file:
        return "js_file"
    if args.js_list:
        return "js_list"
    if args.target:
        return "domain"
    raise SystemExit("No input mode specified. Provide a target, --js, --js-list, or --paste.")


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    mode = determine_mode(args)

    config = ReconConfig(
        enable_behavior_probe=args.probe,
        graph_format=args.graph_format,
        report_format=args.report_format,
    )

    engine = ReconEngine(config=config)

    try:
        if mode == "domain":
            result = engine.scan_domain(args.target)
        elif mode == "js_file":
            # ensure the JS file exists before trying to open it
            import os
            if not args.js_file or not os.path.isfile(args.js_file):
                raise SystemExit(f"JavaScript file not found: {args.js_file}")
            result = engine.scan_js_file(args.js_file)
        elif mode == "js_list":
            if not os.path.isfile(args.js_list):
                raise SystemExit(f"JS list file not found: {args.js_list}")
            with open(args.js_list, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            result = engine.scan_js_urls(urls)
        elif mode == "paste":
            js_code = read_stdin()
            result = engine.scan_js_snippet(js_code)
        else:
            raise SystemExit(f"Unknown mode: {mode}")
    except FileNotFoundError as e:
        raise SystemExit(f"I/O error: {e}")
    except Exception as e:
        # catch unexpected errors and display a clean message
        raise SystemExit(f"Scan failed: {e}")

    output_str = engine.render_report(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
    else:
        sys.stdout.write(output_str + ("\n" if not output_str.endswith("\n") else ""))


if __name__ == "__main__":
    main()

