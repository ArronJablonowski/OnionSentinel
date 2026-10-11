import ast


import builtins


import importlib


import json


from pathlib import Path


import subprocess


import symtable


import sys


from typing import Optional


import unittest


ROOT = Path(__file__).resolve().parents[1]


CONTRACT_PATH = ROOT / "operations" / "quality" / "modularization-contracts.json"


INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


QUERY_RUNTIME_INSTALLER_PATH = (
    ROOT / "n8n" / "bin" / "install-investigation-query-runtime.py"
)


def load_contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def top_level_symbols(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.add(node.name)
        elif isinstance(node, ast.Assign):
            symbols.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
            if any(
                isinstance(target, ast.Name) and target.id == "__all__"
                for target in node.targets
            ):
                try:
                    exported = ast.literal_eval(node.value)
                except (TypeError, ValueError):
                    exported = ()
                if isinstance(exported, (list, tuple, set)):
                    symbols.update(str(name) for name in exported)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            symbols.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            symbols.update(alias.asname or alias.name for alias in node.names)
    return symbols


def top_level_function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing top-level function: {name}")


def top_level_function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


class _ReferenceContextVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.annotation_names: set[str] = set()
        self.runtime_names: set[str] = set()
        self._annotation_depth = 0

    def _visit_annotation(self, node: Optional[ast.AST]) -> None:
        if node is None:
            return
        self._annotation_depth += 1
        try:
            self.visit(node)
        finally:
            self._annotation_depth -= 1

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            target = (
                self.annotation_names
                if self._annotation_depth
                else self.runtime_names
            )
            target.add(node.id)

    def visit_arg(self, node: ast.arg) -> None:
        self._visit_annotation(node.annotation)

    def _visit_function(self, node: ast.AST) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        self._visit_annotation(node.returns)
        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.target)
        self._visit_annotation(node.annotation)
        if node.value is not None:
            self.visit(node.value)


def undefined_global_names(source: str, filename: str) -> set[str]:
    tree = ast.parse(source, filename=filename)
    postponed_annotations = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )
    annotation_only: set[str] = set()
    if postponed_annotations:
        visitor = _ReferenceContextVisitor()
        visitor.visit(tree)
        annotation_only = visitor.annotation_names - visitor.runtime_names

    table = symtable.symtable(source, filename, "exec")
    defined = {
        symbol.get_name()
        for symbol in table.get_symbols()
        if symbol.is_imported()
        or symbol.is_assigned()
        or symbol.is_namespace()
    }
    referenced: set[str] = set()

    def collect(scope: symtable.SymbolTable) -> None:
        referenced.update(
            symbol.get_name()
            for symbol in scope.get_symbols()
            if symbol.is_global() and symbol.is_referenced()
        )
        for child in scope.get_children():
            collect(child)

    collect(table)
    allowed = set(dir(builtins)) | {
        "__conditional_annotations__",
        "__file__",
        "__name__",
    }
    return referenced - defined - allowed - annotation_only
