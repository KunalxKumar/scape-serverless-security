"""Task 7: CI/CD Manifest Generator (Static Analyzer).

Parses Python Lambda function source code using the AST module to extract
all intended AWS API calls. Produces a deployment manifest that can be:
  - Committed alongside the function code
  - Validated in CI/CD pipelines before deployment
  - Fed into the SCAPE engine as a pre-approved action whitelist

Supports:
  - boto3.client('service').method() patterns
  - boto3.resource('service').Collection/method patterns
  - Variable-assigned clients (client = boto3.client('s3'); client.get_object())
  - Nested function calls and class methods
"""

import ast
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


# Maps boto3 service names to CloudTrail eventSource prefixes
SERVICE_TO_CLOUDTRAIL = {
    "s3": "s3",
    "dynamodb": "dynamodb",
    "sqs": "sqs",
    "sns": "sns",
    "lambda": "lambda",
    "iam": "iam",
    "sts": "sts",
    "logs": "logs",
    "ec2": "ec2",
    "kms": "kms",
    "secretsmanager": "secretsmanager",
    "ssm": "ssm",
    "events": "events",
    "stepfunctions": "stepfunctions",
    "cloudwatch": "cloudwatch",
    "kinesis": "kinesis",
    "firehose": "firehose",
    "apigateway": "apigateway",
    "cognito-idp": "cognito-idp",
    "ses": "ses",
    "cloudformation": "cloudformation",
    "rds": "rds",
    "ecs": "ecs",
    "ecr": "ecr",
    "glue": "glue",
    "athena": "athena",
    "redshift": "redshift",
}

# Maps common boto3 method names to CloudTrail action names
# (CamelCase in CloudTrail, snake_case in boto3)
def _snake_to_camel(name: str) -> str:
    """Convert snake_case to CamelCase (e.g. get_object -> GetObject)."""
    return "".join(word.capitalize() for word in name.split("_"))


class Boto3CallVisitor(ast.NodeVisitor):
    """AST visitor that extracts boto3 client/resource API calls."""

    def __init__(self):
        self.services: Set[str] = set()
        self.actions: Set[str] = set()  # "service:Action" format
        self.resources: Dict[str, Set[str]] = defaultdict(set)  # action -> resource patterns
        self.client_vars: Dict[str, str] = {}  # variable_name -> service_name
        self.transitions: List[Tuple[str, str]] = []  # ordered (prev_action, next_action)
        self._last_action: Optional[str] = None

    def visit_Assign(self, node: ast.Assign):
        """Track client = boto3.client('service') assignments."""
        if isinstance(node.value, ast.Call):
            service = self._extract_boto3_client_call(node.value)
            if service:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.client_vars[target.id] = service
                        self.services.add(service)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect boto3 API method calls."""
        # Pattern 1: boto3.client('s3').get_object(...)
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr

            # Direct chained call: boto3.client('s3').get_object()
            if isinstance(node.func.value, ast.Call):
                service = self._extract_boto3_client_call(node.func.value)
                if service and method_name != 'client' and method_name != 'resource':
                    self._record_action(service, method_name, node)

            # Variable-based call: client.get_object()
            elif isinstance(node.func.value, ast.Name):
                var_name = node.func.value.id
                if var_name in self.client_vars:
                    service = self.client_vars[var_name]
                    if not method_name.startswith('_'):
                        self._record_action(service, method_name, node)

            # Check for boto3.client() itself (not a method call on client)
            service = self._extract_boto3_client_call(node)
            if service:
                self.services.add(service)

        self.generic_visit(node)

    def _extract_boto3_client_call(self, node: ast.Call) -> Optional[str]:
        """Extract service name from boto3.client('service') or boto3.resource('service')."""
        if not isinstance(node.func, ast.Attribute):
            return None
        if node.func.attr not in ('client', 'resource'):
            return None
        if not isinstance(node.func.value, ast.Name):
            return None
        if node.func.value.id != 'boto3':
            return None
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value
        # Check keyword: boto3.client(service_name='s3')
        for kw in node.keywords:
            if kw.arg == 'service_name' and isinstance(kw.value, ast.Constant):
                return kw.value.value
        return None

    def _record_action(self, service: str, method_name: str, node: ast.Call):
        """Record a detected API action and track transitions."""
        ct_service = SERVICE_TO_CLOUDTRAIL.get(service, service)
        ct_action = _snake_to_camel(method_name)
        action = f"{ct_service}:{ct_action}"
        self.actions.add(action)

        # Track call order for transition extraction
        if self._last_action:
            self.transitions.append((self._last_action, action))
        self._last_action = action

        # Try to extract resource identifiers from keyword arguments
        for kw in node.keywords:
            if kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                if kw.arg.lower() in ('bucket', 'bucketname', 'tablename', 'queueurl',
                                       'functionname', 'loggroupname', 'topicarn',
                                       'streamname', 'secretid', 'keyid', 'rolename'):
                    self.resources[action].add(f"{kw.arg}={kw.value.value}")

        # Also check positional args for known patterns
        if node.args:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    self.resources[action].add(arg.value)


def generate_manifest(function_code_path: str) -> dict:
    """Parse Lambda function code and generate a SCAPE-compatible manifest.

    Args:
        function_code_path: Path to a Python file containing Lambda handler code.

    Returns:
        A manifest dictionary ready for JSON serialization.
    """
    with open(function_code_path, 'r', encoding='utf-8') as f:
        source = f.read()

    tree = ast.parse(source, filename=function_code_path)
    visitor = Boto3CallVisitor()
    visitor.visit(tree)

    # Build transition map
    transitions = defaultdict(list)
    for prev, curr in visitor.transitions:
        if curr not in transitions[prev]:
            transitions[prev].append(curr)

    # Build resource map
    resources = {}
    for action, res_set in visitor.resources.items():
        resources[action] = sorted(res_set)

    manifest = {
        "version": "2.0",
        "source_file": os.path.basename(function_code_path),
        "services_used": sorted(visitor.services),
        "allowed_actions": sorted(visitor.actions),
        "transitions": dict(transitions),
        "resources": resources,
        "shadow_mode": True,
        "generated_by": "scape-manifest-generator",
    }
    return manifest


def generate_manifest_for_directory(directory: str) -> dict:
    """Scan a directory of Python files and merge manifests.

    Useful for multi-file Lambda packages or layers.
    """
    all_actions = set()
    all_services = set()
    all_transitions = defaultdict(list)
    all_resources = defaultdict(set)
    source_files = []

    for root, dirs, files in os.walk(directory):
        # Skip hidden dirs, __pycache__, venv, node_modules
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   ('__pycache__', 'venv', '.venv', 'node_modules', '.git')]
        for fname in files:
            if fname.endswith('.py'):
                fpath = os.path.join(root, fname)
                try:
                    m = generate_manifest(fpath)
                    source_files.append(os.path.relpath(fpath, directory))
                    all_actions.update(m['allowed_actions'])
                    all_services.update(m['services_used'])
                    for prev, nexts in m['transitions'].items():
                        for n in nexts:
                            if n not in all_transitions[prev]:
                                all_transitions[prev].append(n)
                    for action, res_list in m['resources'].items():
                        all_resources[action].update(res_list)
                except (SyntaxError, UnicodeDecodeError):
                    continue

    return {
        "version": "2.0",
        "source_files": sorted(source_files),
        "services_used": sorted(all_services),
        "allowed_actions": sorted(all_actions),
        "transitions": dict(all_transitions),
        "resources": {k: sorted(v) for k, v in all_resources.items()},
        "shadow_mode": True,
        "generated_by": "scape-manifest-generator",
    }


def validate_manifest(manifest: dict, engine_model_path: str) -> dict:
    """Compare a manifest against a trained SCAPE model.

    Returns a report of actions in the manifest that the engine
    has never seen, and actions the engine knows about that aren't
    in the manifest (potential over-permissioning).
    """
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, PROJECT_ROOT)
    from src.scape_engine import SCAPEEngine

    engine = SCAPEEngine.load(engine_model_path)

    manifest_actions = set(manifest.get('allowed_actions', []))
    trained_actions = set(engine.global_action_counts.keys())

    return {
        "manifest_only": sorted(manifest_actions - trained_actions),
        "model_only": sorted(trained_actions - manifest_actions),
        "overlap": sorted(manifest_actions & trained_actions),
        "manifest_count": len(manifest_actions),
        "model_count": len(trained_actions),
        "coverage": len(manifest_actions & trained_actions) / max(len(manifest_actions), 1),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Generate a SCAPE deployment manifest from Lambda source code.")
    parser.add_argument("path", help="Path to a Python file or directory to scan.")
    parser.add_argument("-o", "--output", help="Output JSON file (default: stdout).")
    parser.add_argument("--validate", help="Path to a trained engine JSON to validate against.")
    args = parser.parse_args()

    target = args.path
    if os.path.isdir(target):
        manifest = generate_manifest_for_directory(target)
    elif os.path.isfile(target):
        manifest = generate_manifest(target)
    else:
        print(f"Error: {target} not found.", file=sys.stderr)
        sys.exit(1)

    output_json = json.dumps(manifest, indent=2)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output_json)
        print(f"Manifest written to {args.output}")
        print(f"  Services: {len(manifest['services_used'])}")
        print(f"  Actions:  {len(manifest['allowed_actions'])}")
    else:
        print(output_json)

    if args.validate:
        print("\n--- Manifest Validation ---")
        report = validate_manifest(manifest, args.validate)
        print(f"  Manifest actions:  {report['manifest_count']}")
        print(f"  Model actions:     {report['model_count']}")
        print(f"  Overlap:           {len(report['overlap'])}")
        print(f"  Coverage:          {report['coverage']:.1%}")
        if report['manifest_only']:
            print(f"  New (not in model): {', '.join(report['manifest_only'][:10])}")
        if report['model_only'][:5]:
            print(f"  Missing from manifest (top 5): {', '.join(report['model_only'][:5])}")


if __name__ == "__main__":
    main()
