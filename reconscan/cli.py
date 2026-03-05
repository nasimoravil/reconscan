"""Command-line interface for the reconscan reconnaissance engine.

Provides an intuitive CLI for running reconnaissance scans with multiple input modes:
- Domain scanning: Crawl and analyze a complete web application
- JavaScript file analysis: Analyze a single local JS file
- JavaScript URL list: Download and analyze multiple JS files from URLs
- Stdin/paste mode: Analyze JavaScript code pasted or piped directly

Supports configurable output formats (JSON, Markdown, HTML) and optional
active probing of endpoints and credential validation.
"""

import argparse
import os
import sys
from typing import List, Optional

from .core import ReconEngine, ReconConfig


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the CLI.
    
    Configures all command-line arguments and options including:
    - Input modes (target domain, JS file, URL list, stdin)
    - Scanning options (probing, credential validation)
    - Output formats (JSON, Markdown, HTML)
    
    Returns:
        Configured ArgumentParser instance
    """
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
        "--no-credential-probe",
        dest="credential_probe",
        action="store_false",
        help="Disable runtime credential probing (enabled by default)",
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
    """Read JavaScript code from standard input.
    
    Returns:
        Complete stdin content as string
    """
    return sys.stdin.read()


def determine_mode(args: argparse.Namespace) -> str:
    """Determine the scanning mode from command-line arguments.
    
    Checks which input mode was specified and returns the corresponding mode name.
    Priority: paste > js_file > js_list > target domain
    
    Args:
        args: Parsed command-line arguments from ArgumentParser
    
    Returns:
        String indicating the scanning mode: 'paste', 'js_file', 'js_list', or 'domain'
    
    Raises:
        SystemExit: If no valid input mode is specified
    """
    if args.paste:
        return "paste"
    if args.js_file:
        return "js_file"
    if args.js_list:
        return "js_list"
    if args.target:
        return "domain"
    raise SystemExit("No input mode specified. Provide a target, --js, --js-list, or --paste.")


def print_banner() -> None:
    """Print the reconscan ASCII art banner."""
    banner = """
XXXXXX                       XXX    XX                               
XX  XX                       XXXXX  XX  XXXXX                        
XX  XX  XXXXXX XXXXXX XXXXXX XX  XX XX XX       XXXX   XXXX  XXXX    
XXXXX   XXXXXX X      X   XXXXX   XXXX XXXXXX  XX     XX  X  XX XX   
XX  XX  X      X      X   XXXXX     XX       X XX     X   X  XX  X   
XX  XXX XXXXXX XXXXXX XXXXXX XX     XX XXXXXXX XXXXXX XXXXXX XX  XXXX 
    """
    print(banner)
    print("Advanced Web & JavaScript Reconnaissance Tool", file=sys.stderr)
    print("=" * 70, file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> None:
    """Main entry point for the CLI.
    
    Orchestrates the complete scanning workflow:
    1. Parse command-line arguments
    2. Determine the input mode (domain/JS file/JS list/stdin)
    3. Create ReconEngine with provided configuration
    4. Execute the appropriate scan method
    5. Render the report in the requested format
    6. Output to file or stdout
    
    Args:
        argv: Optional list of command-line arguments. If None, uses sys.argv
    
    Raises:
        SystemExit: On any fatal error (missing files, invalid input, scan failure)
    """
    # Display banner on CLI startup
    print_banner()
    
    parser = build_parser()
    args = parser.parse_args(argv)

    mode = determine_mode(args)

    # Configure the engine with CLI options
    # Note: credential_probe is DISABLED by default for ethical reasons
    config = ReconConfig(
        enable_behavior_probe=args.probe,
        enable_credential_probe=False,  # Always disabled - user can opt-in after seeing results
        graph_format=args.graph_format,
        report_format=args.report_format,
    )

    engine = ReconEngine(config=config)

    try:
        if mode == "domain":
            # Scan complete domain with crawling
            result = engine.scan_domain(args.target)
        elif mode == "js_file":
            # Validate file exists before scanning
            if not args.js_file or not os.path.isfile(args.js_file):
                raise SystemExit(f"JavaScript file not found: {args.js_file}")
            result = engine.scan_js_file(args.js_file)
        elif mode == "js_list":
            # Read list of URLs and scan each one
            if not os.path.isfile(args.js_list):
                raise SystemExit(f"JS list file not found: {args.js_list}")
            with open(args.js_list, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            result = engine.scan_js_urls(urls)
        elif mode == "paste":
            # Analyze JavaScript from stdin
            js_code = read_stdin()
            result = engine.scan_js_snippet(js_code)
        else:
            raise SystemExit(f"Unknown mode: {mode}")
    except FileNotFoundError as e:
        raise SystemExit(f"I/O error: {e}")
    except Exception as e:
        # Display clean error message for unexpected failures
        raise SystemExit(f"Scan failed: {e}")

    # Generate report in requested format
    output_str = engine.render_report(result)

    # Output to file or stdout
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"\n✓ Report generated: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output_str + ("\n" if not output_str.endswith("\n") else ""))

    # Offer credential testing for domain scans with discovered secrets
    if mode == "domain" and result.secrets and args.report_format == "html":
        print("\n" + "="*60, file=sys.stderr)
        print("⚠️  Credential Testing (Optional)", file=sys.stderr)
        print("="*60, file=sys.stderr)
        print(f"\nFound {len(result.secrets)} credential(s). Do you want to test them?", file=sys.stderr)
        print("This will make HTTP requests to the target using the credentials.", file=sys.stderr)
        print("⚠️  Only proceed if you have authorization and understand the risks!", file=sys.stderr)
        
        try:
            response = input("\nTest credentials? (yes/no): ").strip().lower()
            if response in ("yes", "y"):
                print("\nTesting credentials (this may take a moment)...", file=sys.stderr)
                tested_result = engine.probe_credentials(result, args.target)
                
                # Regenerate report with tested credentials
                tested_report = engine.render_report(tested_result)
                
                # Save to a new file or print
                if args.output:
                    tested_output = args.output.replace(".html", "_tested.html")
                    with open(tested_output, "w", encoding="utf-8") as f:
                        f.write(tested_report)
                    print(f"✓ Tested report saved: {tested_output}", file=sys.stderr)
                else:
                    sys.stdout.write(tested_report + ("\n" if not tested_report.endswith("\n") else ""))
        except (EOFError, KeyboardInterrupt):
            # User declined or interrupted
            print("\nSkipping credential testing.", file=sys.stderr)


if __name__ == "__main__":
    main()

