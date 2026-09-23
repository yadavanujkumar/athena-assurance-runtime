"""Tests for the demo application."""

from src.app import greet, safe_process_expression


def test_greet():
    assert greet("ATHENA") == "Hello, ATHENA!"


def test_safe_process_literal():
    assert safe_process_expression("42") == 42
    assert safe_process_expression("[1, 2, 3]") == [1, 2, 3]
    assert safe_process_expression('"hello"') == "hello"
