"""Demo application with an intentional security finding for ATHENA demonstration."""

# INTENTIONAL EXAMPLE: The eval() below is a deliberate demonstration of a
# dangerous pattern that ATHENA is designed to detect. Do not use eval() with
# user-controlled input in production code.

def process_expression(user_input: str) -> object:
    """Process a user-supplied expression.

    WARNING: This is intentionally unsafe for demonstration purposes only.
    ATHENA will detect this pattern and create a finding with remediation guidance.
    """
    # ATHENA DEMO: eval() with user input is a high-severity finding.
    # The recommended fix is to use ast.literal_eval() for literal expressions
    # or an explicit parser for more complex inputs.
    result = eval(user_input)  # noqa: S307 - intentional for ATHENA demo
    return result


def safe_process_expression(user_input: str) -> object:
    """Process a user-supplied expression safely using ast.literal_eval().

    This is the recommended pattern after ATHENA proposes remediation.
    """
    import ast
    result = ast.literal_eval(user_input)
    return result


def greet(name: str) -> str:
    """Return a greeting for the given name."""
    return f"Hello, {name}!"
