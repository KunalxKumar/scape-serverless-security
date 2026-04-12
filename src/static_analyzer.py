def generate_manifest(function_code_path: str) -> dict:
    """
    Parse Lambda function code to extract intended AWS API calls.
    Returns a manifest dictionary.
    """
    import ast

    class Boto3CallVisitor(ast.NodeVisitor):
        def __init__(self):
            self.actions = set()
            self.resource_patterns = {}

        def visit_Call(self, node):
            # Check for boto3.client('service') pattern
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == 'client' and hasattr(node.func.value, 'id') and node.func.value.id == 'boto3':
                    if node.args and isinstance(node.args[0], ast.Constant):
                        service = node.args[0].value
                        # Now look for method calls on this client (in parent nodes, simplified here)
            self.generic_visit(node)

    with open(function_code_path, 'r') as f:
        tree = ast.parse(f.read())
    visitor = Boto3CallVisitor()
    visitor.visit(tree)

    manifest = {
        "version": "1.0",
        "allowed_actions": list(visitor.actions),
        "transitions": {},
        "resources": {},
        "shadow_mode": True
    }
    return manifest
