#!/usr/bin/env python3

"""
Shellens: A Better Linter for Bash and Shell

Enforces strict architectural philosophy, defensive programming, POSIX compliance,
predictable formatting, and visual hierarchy across shell environments
"""

import glob
import os
import re
import subprocess
import sys
import traceback
from collections import Counter, defaultdict


################################################################################
# Define constants
################################################################################

__version__ = "1.0.0"
USAGE_MSG = "Usage: shellens [--markdown] [--strict] [--info] [--sh] [--no-color] <path_to_script1.sh> [path_to_script2.sh ...]"

# Define rule exemptions
INTENTIONAL_GLOBALS = ('verbosity',)

# Define command and keyword constants
BASH4_ARRAY_COMMANDS = ('mapfile', 'readarray')
DECLARATION_COMMANDS = ('declare', 'typeset')
LOGGING_COMMANDS = ('printf', 'log', 'echo')
FALLBACK_COMMANDS = ('exit', 'return') + LOGGING_COMMANDS
MODIFIER_COMMANDS = ('readonly', 'export')
LOCAL_DECLARATION_COMMANDS = ('local', 'declare', 'typeset') + MODIFIER_COMMANDS
NETWORK_COMMANDS = ('curl', 'wget')
SHELL_COMMANDS = ('sh', 'bash')
STANDARD_BINARIES = (
    'ls', 'cd', 'rm', 'grep', 'awk', 'sed', 'cat', 'echo',
    'printf', 'find', 'cp', 'mv'
)

# Define operators
ASSIGNMENT_OPS = ('=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=')
COMPARISON_OPS = ('==', '!=', '<', '>', '<=', '>=', '-eq', '-ne', '-lt', '-gt', '-le', '-ge')
LOGICAL_OPS = ('&&', '||')
REDIR_OPS_ALL = ('>', '>>', '<', '<<', '<<<', '>&', '&>')
REDIR_OPS_SPACING = ('>', '>>', '<', '<<', '<<<')

# Define block boundary constants
BLOCK_CLOSING_KEYWORDS = ('fi', 'done', 'esac', 'elif', 'else')
BLOCK_START_KEYWORDS = ('{', 'do', 'then', 'else', 'elif')

# Define validation exemptions and patterns
EXEMPTION_KEYWORDS = ('http', 'osascript')
GRAMMAR_ARTICLES = ('a', 'an', 'the')
HEADER_TARGET_WIDTH = 80
SHELLCHECK_FUZZY_PATTERNS = (
    r'^Prefer \[\[ \]\] over \[ \] for tests',
    r'appears unused\. Verify use \(or export if used externally\)\.$',
    r'\$/\$\{\} is unnecessary on arithmetic variables\.$'
)
SHFMT_INDENT_ERRORS = (
    'Inconsistent indentation jump',
    'Missing indentation after block start',
    'Odd-numbered indentation',
    'Misaligned closing brace'
)

# Define tool arguments
SHELLCHECK_BASE_ARGS = ('shellcheck', '--format=gcc', '--check-sourced', '--severity=style')
SHELLCHECK_EXTRA_OPTS = ('-o', 'all')
SHFMT_BASE_ARGS = ('shfmt', '--diff', '--indent', '2', '--case-indent', '--binary-next-line')

# Define variable validation constants
IGNORED_UNUSED_VARIABLES = ('_',)
SPECIAL_VARIABLES = (
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '?', '#', '*', '@', '-',
    '$', '!', '_'
)
STANDARD_ENV_VARIABLES = (
    'BASH_REMATCH', 'COMPREPLY', 'EUID', 'FUNCNAME', 'IFS', 'LC_ALL', 'OPTARG',
    'OPTIND', 'PATH', 'PPID', 'PROMPT_COMMAND', 'PS1', 'PS2', 'PS3', 'PS4',
    'PWD', 'REPLY', 'SECONDS', 'TZ', 'USER'
)

# Define AST node type constants
ARGUMENT_NODE_TYPES = ('word', 'number')
COMPOUND_NODE_TYPES = ('compound_statement', 'expansion', 'array', 'subscript')
CONDITIONAL_NODE_TYPES = ('if_statement', 'binary_expression')
EXPANSION_NODE_TYPES = ('expansion', 'simple_expansion', 'command_substitution')
LOOP_STATEMENT_TYPES = ('for_statement', 'c_style_for_statement', 'select_statement')
PIPELINE_NODE_TYPES = ('command', 'while_statement')
STRING_NODE_TYPES = ('string', 'raw_string')
VARIABLE_NODE_TYPES = ('word', 'variable_name')

# Define ANSI escape codes for terminal coloring
C_BLUE = '\033[94m'
C_BOLD = '\033[1m'
C_CYAN = '\033[96m'
C_DIM = '\033[2m'
C_RED = '\033[91m'
C_RESET = '\033[0m'
C_YELLOW = '\033[93m'


################################################################################
# Pre-compiled regular expressions
################################################################################

_DECL_GROUP = r'(?:' + r'|'.join(k + r'\s+' for k in LOCAL_DECLARATION_COMMANDS) + r')'
RE_ARTICLES = re.compile(r'\b(' + '|'.join(GRAMMAR_ARTICLES) + r')\b', re.IGNORECASE)
RE_ASSIGN_MATCH = re.compile(r'^' + _DECL_GROUP + r'?([a-zA-Z_][a-zA-Z0-9_]*)(?:\[.*\])?\+?=')
RE_BLOCK_CLOSING = re.compile(r'^(' + '|'.join(re.escape(k) + r'\b' for k in BLOCK_CLOSING_KEYWORDS) + r'|\})')
RE_CLEAN_DIFF_PREFIX = re.compile(r'^(?:&&|\|\||\||\bthen\b)\s*')
RE_CLEAN_DIFF_SPACE = re.compile(r'\s+')
RE_CLEAN_DIFF_SUFFIX = re.compile(r'\s*(?:\\|;|then|; then|&&|\|\||\|)$')
RE_CMD_ENV = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*(?:\[.*\])?\+?=[^\s]*\s+[^\s\\#]')
RE_COMMENT_PREFIX = re.compile(r'^\s*#')
RE_COMMENTED_ASSIGNMENT = re.compile(r'^\s*#\s*[a-zA-Z0-9_]+\s*=')
RE_COMMENTED_BLOCK_START = re.compile(
    r'^\s*#\s*(if\s+\[|for\s+.*?\s+in|while\s+\[|case\s+.*?\s+in|echo\s+["\'$]|'
    r'printf\s+["\']|set\s+-[a-zA-Z]|export\s+[a-zA-Z]|local\s+[a-zA-Z]|'
    r'readonly\s+[a-zA-Z])\b'
)
RE_DECL_PREFIX = re.compile(r'^' + _DECL_GROUP)
RE_DIFF_HUNK_START = re.compile(r'-(\d+)')
RE_ECHO_BIN = re.compile(r'\becho\b')
RE_EVALUATED_BOOLEAN = re.compile(r'^"?\$\{[a-zA-Z0-9_]+:-(true|false)\}"?$')
RE_HEREDOC_START = re.compile(r'<<\s*([-]?)\s*[\'"]?([a-zA-Z0-9_-]+)[\'"]?')
RE_LINE_COMMENT_STRIP = re.compile(r'\s*#.*$')
RE_LINE_VARS = re.compile(r'(?:\b|^)' + _DECL_GROUP + r'?([a-zA-Z_][a-zA-Z0-9_]*)(?:\[.*\])?\+?=')
RE_LONG_ASSIGNMENT = re.compile(r'^\s*([a-zA-Z0-9_]+(\+?=)?\s*\(?\s*["\']?[^ ]{60,})')
RE_MATH_END_SPACING = re.compile(r'(?<!\s)(?<!\()\)\)')
RE_MATH_INCREMENT = re.compile(r'=\$\(\(.*?[+-].*?\)\)')
RE_MATH_START_SPACING = re.compile(r'\(\((?!\s|\))')
RE_POSITIONAL_ARG = re.compile(r'\$\{?\d+')
RE_SET_FLAGS_E = re.compile(r'-[a-zA-Z]*e')
RE_SET_FLAGS_U = re.compile(r'-[a-zA-Z]*u')
RE_SET_FLAGS_X = re.compile(r'-[a-zA-Z]*x')
RE_SHELLCHECK_CODE = re.compile(r'\[(SC\d+)\]')
RE_SHELLCHECK_OUTPUT = re.compile(r'^[^:]+:(\d+):\d+: ([^:]+): (.*)$')
RE_STRINGS = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
RE_STYLE_INDENT_MSG = re.compile(r'^STYLE: (' + '|'.join(SHFMT_INDENT_ERRORS) + r')')
RE_THEN_AFTER_PAREN = re.compile(r'\);\s*then\s*:')
RE_TRAILING_PERIOD = re.compile(r'(?:\.|\.\.\.)\s*$')
RE_TRAILING_PERIOD_OUTPUT = re.compile(r'[^.]\.\s*(?:\\n|\n)*"$')
RE_TRAILING_WHITESPACE_BACKSLASH = re.compile(r'\\\s+$')
RE_VALID_VAR_NAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
RE_VAR_EXPANSION_NAME = re.compile(r'\$\{([a-zA-Z0-9_]+)')
RE_VAR_GUARDED = re.compile(r'\$\{([a-zA-Z_][a-zA-Z0-9_]*):?\?|\$\{([a-zA-Z_][a-zA-Z0-9_]*):-?')
RE_VAR_SHELLCHECK_OVERRIDE = re.compile(r'\$\{([a-zA-Z0-9_]+)-?\}')
RE_VAR_UNBOUND_CHECK = re.compile(r'\$([a-zA-Z_][a-zA-Z0-9_]*|[1-9][0-9]*)\b|\$\{([a-zA-Z_][a-zA-Z0-9_]*|[1-9][0-9]*)(\[[@*]\])?\}')

################################################################################


class DependencyError(Exception):
    """Exception raised for missing external dependencies."""
    pass


try:
    import tree_sitter_bash as tsbash
    from tree_sitter import Language, Parser
    BASH_LANGUAGE = Language(tsbash.language())
    TS_PARSER = Parser(BASH_LANGUAGE)
except ImportError:
    TS_PARSER = None

_ast_cache = {}


def clear_ast_cache():
    """Clear internal AST cache"""
    _ast_cache.clear()


def get_color(category):
    """Return appropriate ANSI color code based on issue category"""
    if category in ('SAFETY', 'WARNING', 'SHELLCHECK ERROR', 'SHELLCHECK WARNING'):
        return C_RED
    if category in ('DEAD CODE', 'SCOPE'):
        return C_YELLOW
    if category in ('COMPLEXITY', 'NOTICE'):
        return C_CYAN
    if category in ('STYLE', 'SHFMT', 'SHELLCHECK STYLE', 'SHELLCHECK INFO'):
        return C_BLUE
    return C_RESET


class ASTVisitor:
    """Walk tree-sitter AST"""
    def __init__(self, source_code):
        """Initialize instance"""
        self.source_code = source_code

    def visit(self, node):
        """Dispatch node to specific visitor method"""
        method_name = f"visit_{node.type}"
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """Process children nodes recursively"""
        for child in node.children:
            self.visit(child)

    def get_text(self, node):
        """Extract text from node"""
        if not node:
            return ""
        return self.source_code[node.start_byte:node.end_byte].decode('utf-8', errors='replace')


class DeadCodeVisitor(ASTVisitor):
    """Visitor for analyzing cross-file function and variable usage"""
    def __init__(self, source_code, filepath):
        """Initialize instance"""
        super().__init__(source_code)
        self.filepath = filepath
        self.global_funcs = {}
        self.global_vars = {}
        self.all_words = []
        self.all_var_usages = []
        self.in_function = False

    def visit_function_definition(self, node):
        """Inspect function definition node"""
        name_node = None

        # Extract function name from node children
        for child in node.children:
            if child.type == 'word':
                name_node = child
                break

        if name_node:
            func_name = self.get_text(name_node)
            if func_name not in self.global_funcs:
                self.global_funcs[func_name] = []
            self.global_funcs[func_name].append((self.filepath, name_node.start_point[0] + 1))

        old_in_function = self.in_function
        self.in_function = True
        self.generic_visit(node)
        self.in_function = old_in_function

    def visit_variable_assignment(self, node):
        """Inspect variable assignment node"""
        is_global = True
        is_export = False
        parent = node.parent

        # Check if assignment is part of declaration command
        if parent and parent.type == 'declaration_command':
            decl_type = self.get_text(parent.children[0])

            if decl_type == 'export':
                is_export = True

            if decl_type == 'local':
                is_global = False
            elif decl_type in DECLARATION_COMMANDS:
                has_g = any(self.get_text(c) == '-g' for c in parent.children if c.type == 'word')
                if not has_g and self.in_function:
                    is_global = False

        name_node = None

        # Extract variable name from node children
        for child in node.children:
            if child.type == 'variable_name':
                name_node = child
                break
            if child.type == 'subscript':
                for sub in child.children:
                    if sub.type == 'variable_name':
                        name_node = sub
                        break
                if name_node:
                    break

        if name_node:
            var_name = self.get_text(name_node)

            if is_export:
                self.all_var_usages.append(var_name)

            if is_global:
                is_env_override = False

                # Check parent command for environment overrides
                if parent and parent.type == 'command':
                    for c in parent.children:
                        if c.type == 'command_name':
                            if c.start_point[0] == node.start_point[0]:
                                is_env_override = True
                                break

                            text_between = self.source_code[node.end_byte:c.start_byte].decode('utf-8', errors='replace')
                            if '\\\n' in text_between.replace('\\\r\n', '\\\n'):
                                is_env_override = True
                                break

                # Register global variable
                if not is_env_override:
                    if var_name not in self.global_vars:
                        self.global_vars[var_name] = []
                    self.global_vars[var_name].append((self.filepath, name_node.start_point[0] + 1))

        self.generic_visit(node)

    def visit_word(self, node):
        """Inspect word node"""
        self.all_words.append(self.get_text(node))
        self.generic_visit(node)

    def visit_raw_string(self, node):
        """Inspect raw string node to catch embedded function calls"""
        text = self.get_text(node)
        self.all_words.extend(re.findall(r'[a-zA-Z0-9_-]+', text))
        self.generic_visit(node)

    def visit_string_content(self, node):
        """Inspect string content node to catch embedded function calls"""
        text = self.get_text(node)
        self.all_words.extend(re.findall(r'[a-zA-Z0-9_-]+', text))
        self.generic_visit(node)

    def visit_variable_name(self, node):
        """Inspect variable name node"""
        text = self.get_text(node)
        self.all_words.append(text)

        parent = node.parent
        is_lhs = False

        # Identify Left-Hand Side assignments
        if parent:
            if parent.type == 'variable_assignment' and parent.children[0] == node:
                is_lhs = True
            elif parent.type == 'declaration_command':
                is_lhs = True
            elif parent.type in LOOP_STATEMENT_TYPES:
                is_lhs = True

        # Track Right-Hand Side usage
        if not is_lhs:
            self.all_var_usages.append(text)

        self.generic_visit(node)


def precompute_header_lines(orig_lines):
    """O(N) precomputation of header block line numbers."""
    header_lines = set()
    in_header = False
    for i, line in enumerate(orig_lines):
        if line.strip().startswith('#####'):
            in_header = not in_header
        elif in_header:
            header_lines.add(i + 1)
    return header_lines


class FormatVisitor(ASTVisitor):
    """Visitor for line-by-line formatting, spacing, and styling checks"""
    def __init__(self, source_code, filepath, orig_lines, strict=False, info=False):
        """Initialize instance"""
        super().__init__(source_code)
        self.filepath = filepath
        self.orig_lines = orig_lines
        self.strict = strict
        self.info = info
        self.issues = defaultdict(list)
        self.header_lines = precompute_header_lines(orig_lines)

        self.has_errexit = False
        self.has_nounset = False
        self.has_pipefail = False
        self.is_sh_script = False

        if orig_lines and orig_lines[0].startswith('#!') and 'sh' in orig_lines[0] and 'bash' not in orig_lines[0]:
            self.is_sh_script = True

        self.in_function = False
        self.current_func_name = ""
        self.current_func_start_line = 0
        self.func_complexity = 1
        self.func_exec_lines = 0
        self.has_main_wrapper = False

        self.local_vars_in_func = set()
        self.uppercase_assignments = []
        self.standalone_modifiers = {'readonly': set(), 'export': set()}
        self.heredoc_lines = set()
        self.initialized_vars = set()
        self.naked_readonly_candidates = []

        self.has_seen_code = False
        self.last_comment_line = -2
        self.last_printf_line = -2
        self.in_header_block = False
        self.multiline_string_lines = set()

    def add_issue(self, line_num, message):
        """Record issue at specified line"""
        if message not in self.issues[line_num]:
            self.issues[line_num].append(message)

    def _process_string_node(self, node):
        """Record lines spanning multi-line strings"""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        if start_line != end_line:
            for line_idx in range(start_line, end_line + 1):
                self.multiline_string_lines.add(line_idx)
        self.generic_visit(node)

    def visit_string(self, node):
        """Inspect string node"""
        self._process_string_node(node)

    def visit_raw_string(self, node):
        """Inspect raw string node"""
        self._process_string_node(node)

    def visit_heredoc_body(self, node):
        """Inspect heredoc body node"""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        for ln in range(start_line, end_line + 1):
            self.heredoc_lines.add(ln)
        self.generic_visit(node)

    def visit(self, node):
        """Dispatch node to specific visitor method"""
        if node.type not in ('comment', 'program', 'ERROR') and not self.has_seen_code:
            self.has_seen_code = True
        return super().visit(node)

    def visit_ERROR(self, node):
        """Catch tree-sitter parse errors"""
        line_num = node.start_point[0] + 1
        self.add_issue(line_num, "FORMAT: Unparseable syntax detected. This is highly unconventional Bash code and disrupts static analysis.")
        self.generic_visit(node)

    def visit_comment(self, node):
        """Inspect comment node"""
        line_num = node.start_point[0] + 1
        text = self.get_text(node).strip()

        # Determine if comment is inline
        is_inline = not self.orig_lines[line_num - 1].lstrip().startswith('#')

        # Identify commented code
        is_commented_code = bool(RE_COMMENTED_ASSIGNMENT.match(text) or RE_COMMENTED_BLOCK_START.search(text))

        if is_commented_code:
            self.last_comment_line = line_num
            return

        # Process standard code comments and header blocks
        if (self.has_seen_code or text.startswith('#####')) and text.startswith('#') and not text.startswith('# shellcheck'):

            # Stateless header check
            is_in_header = line_num in self.header_lines

            if not is_inline:

                # Check for contiguous comment blocks
                if self.last_comment_line != -2 and line_num > self.last_comment_line + 1:

                    # Verify code exists between distinct comment blocks
                    has_code = False
                    for ln in range(self.last_comment_line + 1, line_num):
                        if self.orig_lines[ln - 1].strip() != '':
                            has_code = True
                            break
                    if not has_code and not text.startswith('#####'):
                        if self.orig_lines[self.last_comment_line - 1].strip().startswith('#####'):
                            if line_num > self.last_comment_line + 2:
                                self.add_issue(line_num, "FORMAT: Comment must be preceded by exactly one empty line.")
                        else:
                            self.add_issue(line_num, "STYLE: No code between this comment and previous comment block.")

            # Validate header block formatting
            if text.startswith('#####'):
                if self.strict:
                    if len(text) != 80 or not all(c == '#' for c in text):
                        self.add_issue(line_num, f"STYLE: Header block must be exactly 80 '#' characters (found {len(text)}).")

                    # Check preceding empty lines for header
                    if line_num > 2:
                        prev_line_1 = self.orig_lines[line_num - 2].strip()
                        if prev_line_1 != '' and not prev_line_1.startswith('#'):
                            self.add_issue(line_num, "STYLE: Header block must be preceded by 1 or 2 empty lines.")

            elif is_in_header:
                pass
            else:

                # Catch post-header padding missing empty line
                if not is_inline and line_num == self.last_comment_line + 1:
                    prev_line_text = self.orig_lines[line_num - 2].strip()
                    if prev_line_text.startswith('#####'):
                        self.add_issue(line_num, "STYLE: Comment must be preceded by exactly one empty line. Standard comments cannot be attached to bottom of header block.")

                content = text[1:].strip()

                if content and not RE_COMMENT_PREFIX.match(text[1:]):

                    # Scan for grammatical articles in imperative comments
                    if self.strict and RE_ARTICLES.search(content) and not any(k in text for k in EXEMPTION_KEYWORDS):
                        self.add_issue(line_num, "GRAMMAR: Comment contains grammatical articles ('a', 'an', 'the') in imperative mood.")

                    # Catch trailing periods in comments
                    if self.strict and RE_TRAILING_PERIOD.search(content):
                        self.add_issue(line_num, "FORMAT: Comment ends with trailing period.")

            line_str = self.orig_lines[line_num - 1]

            # Check comment indentation alignment
            if line_str.lstrip().startswith('#'):

                # Enforce continuation alignment for comments following inline comments
                if line_num > 1:
                    prev_line_raw = self.orig_lines[line_num - 2]
                    prev_line_no_strings = RE_STRINGS.sub('', prev_line_raw)
                    if '#' in prev_line_no_strings and not prev_line_raw.lstrip().startswith('#'):
                        prev_hash_idx = prev_line_raw.find('#')
                        curr_hash_idx = line_str.find('#')
                        if prev_hash_idx != -1 and curr_hash_idx != -1 and prev_hash_idx != curr_hash_idx:
                            self.add_issue(line_num, "STYLE: Comment indentation mismatch. Comment continuation must perfectly align vertically with preceding inline comment.")
                        if not is_inline:
                            self.last_comment_line = line_num
                        return

                curr_indent = len(line_str) - len(line_str.lstrip())

                next_code_indent = None
                next_code_line = ""
                for idx in range(line_num, len(self.orig_lines)):
                    nl = self.orig_lines[idx]
                    if nl.strip() != '' and not nl.lstrip().startswith('#'):
                        next_code_indent = len(nl) - len(nl.lstrip())
                        next_code_line = nl.lstrip()
                        break

                # Compare comment indentation against subsequent code
                if next_code_indent is not None and curr_indent != next_code_indent:
                    is_closing_block = bool(RE_BLOCK_CLOSING.match(next_code_line))
                    is_valid = False

                    if is_closing_block:
                        prev_code_indent = None
                        for idx in range(line_num - 2, -1, -1):
                            pl = self.orig_lines[idx]
                            if pl.strip() != '' and not pl.lstrip().startswith('#'):
                                prev_code_indent = len(pl) - len(pl.lstrip())
                                break

                        if prev_code_indent is not None and curr_indent == prev_code_indent:
                            is_valid = True
                        elif curr_indent < next_code_indent:
                            is_valid = True

                    if not is_valid:
                        self.add_issue(line_num, "STYLE: Comment indentation mismatch. Align comment with code block it describes.")

                if not is_inline:
                    if line_num == self.last_comment_line + 1:
                        if self.strict and not is_in_header and not text.startswith('#####'):
                            self.add_issue(line_num, "STYLE: Consecutive comment lines detected. Use '#####' header block for extensive documentation or condense to single line.")
                    else:

                        # Validate preceding empty line for comments
                        if line_num > 1:
                            prev_line = self.orig_lines[line_num - 2].strip()
                            is_invalid_spacing = False

                            if prev_line != '':
                                if not prev_line.startswith('#') and prev_line not in BLOCK_START_KEYWORDS and not prev_line.endswith('{'):
                                    if '#' not in self.orig_lines[line_num - 2]:
                                        is_invalid_spacing = True
                            elif line_num > 2 and self.orig_lines[line_num - 3].strip() == '':
                                is_invalid_spacing = True

                            if self.strict and is_invalid_spacing and not text.startswith('#####'):
                                self.add_issue(line_num, "FORMAT: Comment must be preceded by exactly one empty line.")
            if not is_inline:
                self.last_comment_line = line_num
        self.generic_visit(node)

    def visit_declaration_command(self, node):
        """Inspect declaration command node"""
        decl_type = self.get_text(node.children[0])
        line_num = node.start_point[0] + 1

        # Detect Bash 4 features in declarations
        if decl_type in DECLARATION_COMMANDS:
            has_g = any(self.get_text(c) == '-g' for c in node.children if c.type == 'word')
            has_a = any(self.get_text(c) == '-A' for c in node.children if c.type == 'word')
            if has_g or has_a:
                self.add_issue(line_num, "WARNING: 'declare -g' or 'declare -A' detected. This is Bash 4.0+ feature and breaks macOS/POSIX compatibility.")

        # Extract modifiers for standalone evaluation
        if decl_type in MODIFIER_COMMANDS:
            for child in node.children[1:]:
                if child.type in VARIABLE_NODE_TYPES:
                    word_text = self.get_text(child)
                    if '=' not in word_text and not word_text.startswith('-'):
                        self.standalone_modifiers[decl_type].add(word_text)
                        if decl_type == 'readonly':
                            self.naked_readonly_candidates.append((word_text, line_num))
                elif child.type == 'variable_assignment':
                    for sub in child.children:
                        if sub.type == 'variable_name':
                            self.initialized_vars.add(self.get_text(sub))

        # Track locally scoped variables
        if self.in_function and decl_type in LOCAL_DECLARATION_COMMANDS:
            for child in node.children[1:]:
                if child.type == 'variable_name':
                    self.local_vars_in_func.add(self.get_text(child))
                elif child.type == 'variable_assignment':
                    for sub in child.children:
                        if sub.type == 'variable_name':
                            self.local_vars_in_func.add(self.get_text(sub))

        vars_declared = []

        # Aggregate grouped variable declarations
        for child in node.children[1:]:
            if child.type == 'variable_name':
                vars_declared.append(self.get_text(child))
            elif child.type == 'variable_assignment':
                for sub in child.children:
                    if sub.type == 'variable_name':
                        vars_declared.append(self.get_text(sub))

        # Validate alphabetical sorting of declaration lists
        if self.strict and len(vars_declared) > 1 and decl_type in LOCAL_DECLARATION_COMMANDS:
            if vars_declared != sorted(vars_declared):
                self.add_issue(line_num, f"STYLE: Variables in declaration list '{' '.join(vars_declared)}' are not alphabetically sorted.")
        self.generic_visit(node)

    def visit_array(self, node):
        """Inspect array node"""
        text = self.get_text(node)

        # Validate array parenthesis spacing
        if len(text) > 2:
            missing_start = not text.startswith('( ') and not text.startswith('(\n') and not text.startswith('(\t')
            missing_end = not text.endswith(' )') and not text.endswith('\n)') and not text.endswith('\t)')

            start_ln = node.start_point[0] + 1
            end_ln = node.end_point[0] + 1

            if self.strict:
                if missing_start and missing_end and start_ln == end_ln:
                    self.add_issue(start_ln, "FORMAT: Missing spaces inside array initialization '( ... )'.")
                else:
                    if missing_start:
                        self.add_issue(start_ln, "FORMAT: Missing space after array initialization start '( ...'.")
                    if missing_end:
                        self.add_issue(end_ln, "FORMAT: Missing space before closing parenthesis of array '... )'.")
        self.generic_visit(node)

    def visit_process_substitution(self, node):
        """Inspect process substitution node"""
        text = self.get_text(node)

        # Validate process substitution parenthesis spacing
        missing_start = False
        if text.startswith('<(') and not text.startswith('<( ') and not text.startswith('<(\n') and not text.startswith('<(\t'):
            missing_start = True
        elif text.startswith('>(') and not text.startswith('>( ') and not text.startswith('>(\n') and not text.startswith('>(\t'):
            missing_start = True

        missing_end = not text.endswith(' )') and not text.endswith('\n)') and not text.endswith('\t)')

        start_ln = node.start_point[0] + 1
        end_ln = node.end_point[0] + 1

        if self.strict:
            if missing_start and missing_end and start_ln == end_ln:
                self.add_issue(start_ln, "FORMAT: Missing spaces inside process substitution '<( ... )' or '>( ... )'.")
            else:
                if missing_start:
                    self.add_issue(start_ln, "FORMAT: Missing space after process substitution start '<( ...' or '>( ...'.")
                if missing_end:
                    self.add_issue(end_ln, "FORMAT: Missing space before closing parenthesis of process substitution '... )'.")
        self.generic_visit(node)

    def visit_subshell(self, node):
        """Inspect subshell node"""
        text = self.get_text(node)

        # Validate subshell parenthesis spacing
        missing_start = text.startswith('(') and not text.startswith('( ') and not text.startswith('(\n') and not text.startswith('(\t')
        missing_end = not text.endswith(' )') and not text.endswith('\n)') and not text.endswith('\t)')

        start_ln = node.start_point[0] + 1
        end_ln = node.end_point[0] + 1

        if self.strict:
            if missing_start and missing_end and start_ln == end_ln:
                self.add_issue(start_ln, "FORMAT: Missing spaces inside subshell '( ... )'.")
            else:
                if missing_start:
                    self.add_issue(start_ln, "FORMAT: Missing space after subshell start '( ...'.")
                if missing_end:
                    self.add_issue(end_ln, "FORMAT: Missing space before closing parenthesis of subshell '... )'.")

        complexity = self._get_node_complexity(node)
        if complexity >= 10 or (end_ln - start_ln > 20 and complexity >= 2):
            self.add_issue(start_ln, "COMPLEXITY: Subshell monolith detected. Consider modularizing into function.")

        self.generic_visit(node)

    def visit_command_substitution(self, node):
        """Inspect command substitution node"""
        text = self.get_text(node)

        # Validate command substitution parenthesis spacing
        missing_start = False
        if text.startswith('$(') and not text.startswith('$( ') and not text.startswith('$(\n') and not text.startswith('$(\t'):
            if not text.startswith('$(('):
                missing_start = True

        missing_end = False
        if text.endswith(')') and not text.endswith(' )') and not text.endswith('\n)') and not text.endswith('\t)'):
            if not text.endswith('))'):
                missing_end = True

        start_ln = node.start_point[0] + 1
        end_ln = node.end_point[0] + 1

        if self.strict:
            if missing_start and missing_end and start_ln == end_ln:
                self.add_issue(start_ln, "FORMAT: Missing spaces inside command substitution '$( ... )'.")
            else:
                if missing_start:
                    self.add_issue(start_ln, "FORMAT: Missing space after command substitution start '$( ...'.")
                if missing_end:
                    self.add_issue(end_ln, "FORMAT: Missing space before closing parenthesis of command substitution '... )'.")

        complexity = self._get_node_complexity(node)
        if complexity >= 10 or (end_ln - start_ln > 20 and complexity >= 2):
            self.add_issue(start_ln, "COMPLEXITY: Subshell monolith detected. Consider modularizing into function.")

        self.generic_visit(node)

    def visit_pipeline(self, node):
        """Inspect pipeline node"""

        # Check pipeline commands
        commands = [c for c in node.children if c.type in PIPELINE_NODE_TYPES]

        for i in range(len(commands) - 1):
            cmd1 = commands[i]
            cmd2 = commands[i + 1]

            # Detect inefficient grep to awk pipelines
            if cmd1.type == 'command' and cmd2.type == 'command':
                name1 = cmd1.children[0] if cmd1.children else None
                name2 = cmd2.children[0] if cmd2.children else None
                if name1 and name1.type == 'command_name' and name2 and name2.type == 'command_name':
                    if self.get_text(name1) == 'grep' and self.get_text(name2) == 'awk':
                        self.add_issue(cmd2.start_point[0] + 1, "STYLE: Inefficient grep to awk pipeline. Combine 'grep pattern | awk' into 'awk \"/pattern/\"'.")

            # Detect while read pipes
            if cmd2.type == 'while_statement':
                while_cmd = cmd2.children[1] if len(cmd2.children) > 1 else None
                if while_cmd and while_cmd.type == 'command':
                    w_name = while_cmd.children[0] if while_cmd.children else None
                    if w_name and w_name.type == 'command_name' and self.get_text(w_name) == 'read':
                        self.add_issue(cmd2.start_point[0] + 1, "STYLE: Avoid piping into 'while read'. Variables set in loop are lost in subshell. Use 'while read ... < <( cmd )' instead.")

        self.generic_visit(node)

    def visit_command(self, node):
        """Inspect command node"""
        cmd_name = None
        line_num = node.start_point[0] + 1

        # Check for background process execution
        if node.next_sibling and node.next_sibling.type == '&':
            if self.info:
                self.add_issue(line_num, "NOTICE: Background process launched ('&'). Ensure it is tracked, polled, or resolved with 'wait' to prevent orphan processes.")

        def has_dynamic_expansion(n):
            if n.type in EXPANSION_NODE_TYPES:
                return True
            for c in n.children:
                if has_dynamic_expansion(c):
                    return True
            return False

        if node.children:
            for child in node.children:
                if child.type == 'command_name':
                    cmd_name = self.get_text(child)
                    if has_dynamic_expansion(child):
                        if not RE_EVALUATED_BOOLEAN.match(cmd_name):
                            if self.info:
                                self.add_issue(line_num, "NOTICE: Dynamic command execution detected. Executing commands from variables obscures static analysis and poses severe security risk if variable is manipulated.")
                    break

            if node.children[0].type == 'file_redirect' and cmd_name:
                self.add_issue(line_num, "STYLE: Redirections should be placed at end of command statement.")

        # Detect main wrapper execution
        if cmd_name == 'main' and not self.in_function:
            self.has_main_wrapper = True

        # Ban Bash 4 array functions
        if cmd_name in BASH4_ARRAY_COMMANDS:
            self.add_issue(line_num, "WARNING: 'mapfile' or 'readarray' detected. This is Bash 4.0+ feature and breaks macOS/POSIX compatibility.")

        # Ban obsolete grep aliases
        if cmd_name == 'egrep':
            self.add_issue(line_num, "STYLE: Use 'grep -E' instead of 'egrep' for consistent cross-platform behavior.")
        elif cmd_name == 'fgrep':
            self.add_issue(line_num, "STYLE: Use 'grep -F' instead of 'fgrep' for consistent cross-platform behavior.")
        elif cmd_name == 'which':
            self.add_issue(line_num, "STYLE: Use 'command -v' instead of 'which' for portability.")
        elif cmd_name == 'let':
            self.add_issue(line_num, "STYLE: Use Bash arithmetic evaluation '(( ... ))' instead of 'let'.")
        elif cmd_name == 'expr':
            self.add_issue(line_num, "STYLE: Use POSIX arithmetic expansion '$(( ... ))' instead of 'expr'.")

        # Detect sed -i even when wrapped in sudo or run_as_root
        words = [self.get_text(c) for c in node.children]

        has_sed = False
        for w in words:
            if w == 'sed':
                has_sed = True
            elif has_sed and w.startswith('-i'):
                self.add_issue(line_num, "WARNING: 'sed -i' detected. In-place replacement syntax is fundamentally incompatible between GNU and macOS/BSD. Use standard redirection.")
                break

        # Check strict mode declarations
        if cmd_name == 'set':
            args = [self.get_text(c) for c in node.children if c.type == 'word']
            args_str = " ".join(args)

            # Check for debug flags
            if '-x' in args_str or 'xtrace' in args_str or RE_SET_FLAGS_X.search(args_str):
                in_conditional = False
                p = node.parent

                # Check if set -x is inside conditional
                while p:
                    if p.type in CONDITIONAL_NODE_TYPES:
                        in_conditional = True
                        break
                    if p.type == 'list' and any(c.type in LOGICAL_OPS for c in p.children):
                        in_conditional = True
                        break
                    p = p.parent

                if not in_conditional:
                    self.add_issue(line_num, "WARNING: 'set -x' (xtrace) detected. Remove debug flags before committing.")

            # Check for strict mode flags
            if '-e' in args_str or 'errexit' in args_str or RE_SET_FLAGS_E.search(args_str):
                self.has_errexit = True
            if '-u' in args_str or 'nounset' in args_str or RE_SET_FLAGS_U.search(args_str):
                self.has_nounset = True
            if 'pipefail' in args_str:
                self.has_pipefail = True

        # Detect dynamic shell execution
        if cmd_name in SHELL_COMMANDS:
            args = [self.get_text(c) for c in node.children if c.type == 'word']
            if '-c' in args:
                for child in node.children[1:]:
                    if child.type in STRING_NODE_TYPES:
                        inner_code = self.get_text(child)
                        if inner_code.startswith("'") or inner_code.startswith('"'):
                            inner_code = inner_code[1:-1]

                        # Emulate flat regex evaluation for embedded scripts
                        if RE_ECHO_BIN.search(inner_code):
                            self.add_issue(line_num, "STYLE: Use 'printf' instead of 'echo' for consistent cross-platform behavior.")
                        for m in re.finditer(r'(?<![\$\\])\$([a-zA-Z_][a-zA-Z0-9_]*)(?!\])\b', inner_code):
                            var_name = m.group(1)
                            if var_name != '_':
                                self.add_issue(line_num, f"STYLE: Bare variable '${var_name}'. Use curly braces: '${{{var_name}}}'.")

        if cmd_name == 'echo':
            self.add_issue(line_num, "STYLE: Use 'printf' instead of 'echo' for consistent cross-platform behavior.")

        # Enforce printf usage rules
        if cmd_name == 'printf':
            has_array = '[@]' in self.get_text(node) or '[*]' in self.get_text(node)
            has_redir = node.parent and node.parent.type == 'redirected_statement'
            is_complex = has_array or has_redir
            if not is_complex and self.last_printf_line == line_num - 1:
                if self.info:
                    self.add_issue(line_num, "NOTICE: Consecutive 'printf' commands detected. Consider combining them into single multi-line printf.")
            if not is_complex:
                self.last_printf_line = line_num

        # Check for trailing periods in logging commands
        if cmd_name in LOGGING_COMMANDS:
            for child in node.children[1:]:
                if child.type == 'string':
                    text = self.get_text(child)
                    if self.strict and RE_TRAILING_PERIOD_OUTPUT.search(text):
                        self.add_issue(line_num, "STYLE: Terminal output ends with trailing period. Use imperative mood or remove punctuation.")

        # Ban eval command
        if cmd_name == 'eval':
            self.add_issue(line_num, "WARNING: 'eval' command detected. This is severe security risk if input is unsanitized.")

        # Check for excessive chmod permissions
        if cmd_name == 'chmod':
            args = [self.get_text(c) for c in node.children if c.type in ARGUMENT_NODE_TYPES]
            if '777' in args:
                self.add_issue(line_num, "WARNING: 'chmod 777' detected. Use principle of least privilege.")

        # Check for dangerous network piping
        if cmd_name in NETWORK_COMMANDS:
            parent = node.parent
            if parent and parent.type == 'pipeline':
                for p_child in parent.children:
                    if p_child.type == 'command':
                        p_cmd_name = None
                        if p_child.children and p_child.children[0].type == 'command_name':
                            p_cmd_name = self.get_text(p_child.children[0])
                        if p_cmd_name in SHELL_COMMANDS:
                            self.add_issue(line_num, "WARNING: Dangerous pattern detected (curl/wget piped to shell).")

        # Detect double quoted awk scripts
        if cmd_name == 'awk':
            for child in node.children[1:]:
                if child.type == 'string':
                    text = self.get_text(child)
                    if text.startswith('"') and '$' in text:
                        self.add_issue(line_num, "SECURITY: Unsafe awk quoting. Double-quoted awk strings expand variables prematurely. Use single quotes and pass vars via '-v'.")

        # Check for forced kill commands
        if cmd_name == 'kill':
            args = [self.get_text(c) for c in node.children if c.type in ARGUMENT_NODE_TYPES]
            if '-9' in args:
                self.add_issue(line_num, "SAFETY: 'kill -9' detected. SIGKILL does not allow graceful shutdown and can corrupt state. Prefer SIGTERM (default).")

        # Validate read command scope
        if cmd_name == 'read':
            if self.in_function:
                for child in node.children[1:]:
                    if child.type == 'word':
                        word_text = self.get_text(child)
                        if not word_text.startswith('-') and RE_VALID_VAR_NAME.match(word_text):
                            self.initialized_vars.add(word_text)
                            if not self._is_declared_local_in_scope(node, word_text):
                                self.add_issue(line_num, f"SCOPE: Variable '{word_text}' assigned in function without 'local' or 'readonly'.")
            else:
                for child in node.children[1:]:
                    if child.type == 'word':
                        word_text = self.get_text(child)
                        if not word_text.startswith('-') and RE_VALID_VAR_NAME.match(word_text):
                            self.initialized_vars.add(word_text)
        self.generic_visit(node)

    def _get_node_complexity(self, node):
        """Recursively calculate cyclomatic complexity of AST node"""
        complexity = 0
        if node.type in ('if_statement', 'elif_clause', 'for_statement', 'while_statement', 'until_statement', 'case_item'):
            complexity += 1
        elif node.type == 'binary_expression':
            for child in node.children:
                if child.type in LOGICAL_OPS:
                    complexity += 1
        for child in node.children:
            complexity += self._get_node_complexity(child)
        return complexity

    def visit_function_definition(self, node):
        """Inspect function definition node"""
        line_num = node.start_point[0] + 1

        # Reject POSIX function keyword
        if self.strict:
            if self.get_text(node.children[0]) == 'function':
                self.add_issue(line_num, "STYLE: Non-POSIX function declaration. Remove 'function' keyword (use 'foo() {').")

        name_node = None
        for child in node.children:
            if child.type == 'word':
                name_node = child
                break

        if name_node:
            func_name = self.get_text(name_node)

            # Detect shadowed system binaries
            if func_name in STANDARD_BINARIES:
                if self.info:
                    self.add_issue(line_num, f"NOTICE: Function '{func_name}' shadows standard system binary.")

            self.current_func_name = func_name
            self.current_func_start_line = name_node.start_point[0] + 1

        # Initialize isolated function context
        old_in_func = self.in_function
        old_complexity = self.func_complexity
        old_exec_lines = self.func_exec_lines
        old_local_vars = self.local_vars_in_func.copy()

        self.in_function = True
        self.func_complexity = 1
        self.func_exec_lines = 0
        self.local_vars_in_func = set()

        start_line = node.start_point[0]
        end_line = node.end_point[0]

        # Calculate function execution lines
        for i in range(start_line, end_line + 1):
            line = self.orig_lines[i].strip()
            if line and not line.startswith('#') and line not in ('{', '}'):
                self.func_exec_lines += 1

        first_line = self.orig_lines[start_line].strip()
        if first_line.endswith('{'):
            self.func_exec_lines = max(0, self.func_exec_lines - 1)

        self.generic_visit(node)

        # Validate function complexity constraints
        if self.current_func_name != 'main':
            is_complex = self.func_complexity > 15
            is_long = self.func_exec_lines > 50

            if self.info:
                if is_complex and is_long:
                    self.add_issue(self.current_func_start_line, f"COMPLEXITY: Function '{self.current_func_name}' is too complex (Score: {self.func_complexity}, Max: 15) AND too long ({self.func_exec_lines} lines). Consider breaking it down.")
                elif is_complex:
                    self.add_issue(self.current_func_start_line, f"COMPLEXITY: Function '{self.current_func_name}' is too complex (Score: {self.func_complexity}, Max: 15). Consider breaking it down.")
                elif is_long:
                    self.add_issue(self.current_func_start_line, f"COMPLEXITY: Function '{self.current_func_name}' is {self.func_exec_lines} lines of code. Consider modularizing if possible.")

        self.in_function = old_in_func
        self.func_complexity = old_complexity
        self.func_exec_lines = old_exec_lines
        self.local_vars_in_func = old_local_vars

    def visit_compound_statement(self, node):
        """Inspect compound statement node"""
        if len(node.children) >= 2 and self.get_text(node.children[0]) == '((' and self.get_text(node.children[-1]) == '))':

            def walk_math(n):
                """Traverse math node children"""
                if n.type in ('simple_expansion', 'expansion'):
                    self.add_issue(n.start_point[0] + 1, "SAFETY: Variable expansion with '$' used inside math context. Drop '$'.")
                for c in n.children:
                    walk_math(c)
            walk_math(node)
        self.generic_visit(node)

    def visit_if_statement(self, node):
        """Inspect if statement node"""
        if self.in_function:
            self.func_complexity += 1

        line_num = node.start_point[0] + 1

        then_node = None
        for child in node.children:
            if child.type == 'then':
                then_node = child
                break

        # Enforce then keyword placement
        if self.strict and then_node:
            condition_start_line = node.start_point[0]
            condition_end_line = condition_start_line
            for child in node.children:
                if child == then_node:
                    break
                if child.end_point[0] > condition_end_line:
                    condition_end_line = child.end_point[0]

            if condition_end_line == condition_start_line:
                if then_node.start_point[0] > condition_start_line:
                    self.add_issue(line_num, "STYLE: Simple 'if' detected. Put 'then' on same line (e.g., 'if [[ ... ]]; then').")
            else:
                then_line_text = self.orig_lines[then_node.start_point[0]].strip()
                if then_line_text != 'then':
                    if then_line_text.startswith('then'):
                        self.add_issue(then_node.start_point[0] + 1, "FORMAT: Isolated 'then' line contains trailing characters or comments.")
                    elif not RE_THEN_AFTER_PAREN.search(then_line_text):
                        self.add_issue(then_node.start_point[0] + 1, "FORMAT: Multi-line 'if' detected. Place 'then' keyword on its own dedicated line.")

        self.generic_visit(node)

    def visit_elif_clause(self, node):
        """Inspect elif clause node"""
        if self.in_function:
            self.func_complexity += 1
        self.generic_visit(node)

    def visit_for_statement(self, node):
        """Inspect for statement node"""
        if self.in_function:
            self.func_complexity += 1
        for child in node.children:
            if child.type == 'variable_name':
                var_name = self.get_text(child)
                self.initialized_vars.add(var_name)
                if self.in_function and not self._is_declared_local_in_scope(node, var_name):
                    self.add_issue(node.start_point[0] + 1, f"SCOPE: Variable '{var_name}' assigned in function without 'local' or 'readonly'.")
        self.generic_visit(node)

    def visit_while_statement(self, node):
        """Inspect while statement node"""
        if self.in_function:
            self.func_complexity += 1
        self.generic_visit(node)

    def visit_until_statement(self, node):
        """Inspect until statement node"""
        if self.in_function:
            self.func_complexity += 1
        self.generic_visit(node)

    def visit_case_item(self, node):
        """Inspect case item node"""
        line_num = node.start_point[0] + 1
        if self.in_function:
            self.func_complexity += 1

        # Validate presence of explicit exit in fallback routines
        is_fallback = False
        has_commands = False

        for child in node.children:
            if child.type in ('extglob_pattern', 'word'):
                if self.get_text(child) == '*':
                    is_fallback = True
            elif child.type == 'command':
                cmd_name = None
                if child.children and child.children[0].type == 'command_name':
                    cmd_name = self.get_text(child.children[0])
                if cmd_name in FALLBACK_COMMANDS:
                    has_commands = True
                    break

        if self.strict and is_fallback and not has_commands:
            self.add_issue(line_num, "STYLE: Case fallback '*)' should contain explicit exit, return, or log command.")

        self.generic_visit(node)

    def _check_math_assign(self, node):
        """Verify math assignment scope"""
        for child in node.children:
            if child.type == 'variable_name':
                var_name = self.get_text(child)
                self.initialized_vars.add(var_name)
                if self.in_function and not self._is_declared_local_in_scope(node, var_name):
                    self.add_issue(node.start_point[0] + 1, f"SCOPE: Variable '{var_name}' assigned in function without 'local' or 'readonly'.")

    def visit_postfix_expression(self, node):
        """Inspect postfix expression node"""
        self._check_math_assign(node)
        self.generic_visit(node)

    def visit_prefix_expression(self, node):
        """Inspect prefix expression node"""
        self._check_math_assign(node)
        self.generic_visit(node)

    def visit_binary_expression(self, node):
        """Inspect binary expression node"""
        for child in node.children:
            if child.type in LOGICAL_OPS and self.in_function:
                self.func_complexity += 1
            elif child.type in ASSIGNMENT_OPS:
                self._check_math_assign(node)
        self.generic_visit(node)

    def _is_declared_local_in_scope(self, node, var_name):
        """Check if variable is declared local in scope"""
        curr = node

        # Traverse upwards until function definition
        while curr and curr.type != 'function_definition':
            parent = curr.parent
            if parent:

                # Prevent else and elif clauses from inheriting locals from parent conditional
                if not (parent.type == 'if_statement' and curr.type in ('elif_clause', 'else_clause')):
                    for child in parent.children:
                        if child.type == 'declaration_command':

                            # Inspect declaration statements
                            decl_type = self.get_text(child.children[0])
                            if decl_type in LOCAL_DECLARATION_COMMANDS:
                                has_g = any(self.get_text(c) == '-g' for c in child.children if c.type == 'word')
                                if not has_g:
                                    for sub in child.children[1:]:
                                        if sub.type == 'variable_name' and self.get_text(sub) == var_name:
                                            return True
                                        if sub.type == 'variable_assignment':
                                            for ssub in sub.children:
                                                if ssub.type == 'variable_name' and self.get_text(ssub) == var_name:
                                                    return True

                        elif child.type == 'command':

                            # Inspect generic commands acting as declarations
                            cmd_name = None
                            if child.children and child.children[0].type == 'command_name':
                                cmd_name = self.get_text(child.children[0])

                            if cmd_name in LOCAL_DECLARATION_COMMANDS:
                                has_g = any(self.get_text(c) == '-g' for c in child.children if c.type == 'word')
                                if not has_g:
                                    for sub in child.children[1:]:
                                        if sub.type in VARIABLE_NODE_TYPES and self.get_text(sub) == var_name:
                                            return True
            curr = parent
        return False

    def visit_variable_assignment(self, node):
        """Inspect variable assignment node"""
        parent = node.parent
        is_local = False
        is_readonly = False
        is_export = False

        line_num = node.start_point[0] + 1

        # Evaluate variable scope modifiers from declaration command
        if parent and parent.type == 'declaration_command':
            decl_type = self.get_text(parent.children[0])

            if decl_type == 'local':
                is_local = True
            elif decl_type == 'readonly':
                is_readonly = True
            elif decl_type == 'export':
                is_export = True
            elif decl_type in DECLARATION_COMMANDS:
                has_g = any(self.get_text(c) == '-g' for c in parent.children if c.type == 'word')

                # Infer local scope for generic declarations inside functions lacking global flag
                if not has_g and self.in_function:
                    is_local = True

        # Locate assigned variable name
        name_node = None
        for child in node.children:
            if child.type == 'variable_name':
                name_node = child
                break

            # Map subscript children to handle array assignments
            if child.type == 'subscript':
                for sub in child.children:
                    if sub.type == 'variable_name':
                        name_node = sub
                        break
                if name_node:
                    break

        if name_node:
            var_name = self.get_text(name_node)
            line_num = name_node.start_point[0] + 1
            self.initialized_vars.add(var_name)

            if self.in_function:

                # Detect unapproved global assignments bypassing local modifiers
                if var_name not in INTENTIONAL_GLOBALS and var_name not in STANDARD_ENV_VARIABLES and not is_export and not is_local and not is_readonly:
                    is_env_override = False
                    if parent and parent.type == 'command':
                        for c in parent.children:
                            if c.type == 'command_name':

                                # Check for inline environment overrides preceding commands
                                if c.start_point[0] == node.start_point[0]:
                                    is_env_override = True
                                    break

                                # Handle line continuations separating override from command
                                text_between = self.source_code[node.end_byte:c.start_byte].decode('utf-8', errors='replace')
                                if '\\\n' in text_between.replace('\\\r\n', '\\\n'):
                                    is_env_override = True
                                    break

                    is_subshell = False
                    curr = parent
                    while curr:
                        if curr.type in ('subshell', 'command_substitution', 'process_substitution'):
                            is_subshell = True
                            break
                        curr = curr.parent

                    if not is_subshell and not is_env_override and not self._is_declared_local_in_scope(node, var_name):
                        self.add_issue(line_num, f"SCOPE: Variable '{var_name}' assigned in function without 'local' or 'readonly'.")

            # Validate uppercase naming conventions for constants
            if var_name.isupper() and not var_name.startswith('SC_'):
                if var_name not in STANDARD_ENV_VARIABLES:
                    if self.info:
                        self.add_issue(line_num, f"NOTICE: Variable '{var_name}' is UPPERCASE. Is this really user-configurable parameter?")
                    if not is_readonly and not is_export:
                        self.uppercase_assignments.append((var_name, line_num))

        self.generic_visit(node)

    def visit_test_command(self, node):
        """Inspect test command node"""
        line_num = node.start_point[0] + 1
        text = self.get_text(node)

        # Validate Bash double brackets
        if text.startswith('[['):
            for child in node.children:

                # Search for binary expression inside test
                if child.type == 'binary_expression':
                    for sub in child.children:

                        # Reject single equals sign in Bash tests
                        if sub.type == '=':
                            self.add_issue(line_num, "STYLE: Use '==' instead of '=' for string comparison inside Bash '[[ ... ]]' tests.")

        # Reject POSIX single brackets
        elif text.startswith('['):
            if not self.is_sh_script:
                self.add_issue(line_num, "STYLE: Use Bash keyword '[[ ... ]]' instead of POSIX '[ ... ]' tests.")

        # Extract variables modified by ShellCheck overrides
        m = RE_VAR_SHELLCHECK_OVERRIDE.search(text)
        if m:
            self.initialized_vars.add(m.group(1))

        def _check_unary(n):
            """Recursively check unary expressions for unsafe checks"""
            if n.type == 'unary_expression':
                op = None
                target = None
                for c in n.children:
                    if c.type == 'test_operator':
                        op = self.get_text(c)
                    else:
                        target = c

                # Detect naked variable checks crashing under strict mode
                if op in ('-z', '-n') and target:
                    target_text = self.get_text(target)
                    if '"$' in target_text and ':-' not in target_text and '-}' not in target_text and '+1}' not in target_text:
                        var_match = RE_VAR_UNBOUND_CHECK.search(target_text)
                        if var_match:
                            v = (var_match.group(1) or var_match.group(2)) + (var_match.group(3) or "")
                            is_positional = bool(var_match.group(1) and var_match.group(1).isdigit()) or bool(var_match.group(2) and var_match.group(2).isdigit())

                            if is_positional:
                                if self.strict:
                                    self.add_issue(n.start_point[0] + 1, f"SAFETY: Unsafe unbound check for '${{{v}}}'. Use '${{{v}-}}' inside -z/-n checks to prevent nounset crashes.")
                            else:
                                self.add_issue(n.start_point[0] + 1, f"SAFETY: Unsafe unbound check for '${{{v}}}'. Use '${{{v}-}}' inside -z/-n checks to prevent nounset crashes.")

            for c in n.children:
                _check_unary(c)
        _check_unary(node)

        self.generic_visit(node)

    def visit_simple_expansion(self, node):
        """Inspect simple expansion node"""
        line_num = node.start_point[0] + 1
        var_name = self.get_text(node)[1:]

        if var_name not in SPECIAL_VARIABLES:
            parent = node.parent

            # Enforce curly braces for bare variables
            if parent and parent.type not in COMPOUND_NODE_TYPES:
                self.add_issue(line_num, f"STYLE: Bare variable '${var_name}'. Use curly braces: '${{{var_name}}}'.")
        self.generic_visit(node)

    def visit_expansion(self, node):
        """Inspect parameter expansion node"""
        text = self.get_text(node)
        m = RE_VAR_EXPANSION_NAME.search(text)
        if m:
            var_name = m.group(1)

            # Match legacy ShellCheck guarded_vars behavior
            if RE_VAR_GUARDED.search(text):
                self.initialized_vars.add(var_name)
        self.generic_visit(node)

    def visit_number(self, node):
        """Inspect number node"""
        line_num = node.start_point[0] + 1
        num_str = self.get_text(node)
        if num_str.isdigit():
            val = int(num_str)

            # Detect potential magic numbers bypassing standard logic constants
            if self.strict and val > 9 and val not in (80, 255, 1492):
                is_magic = False
                parent = node.parent
                if parent:
                    if parent.type == 'command':
                        if parent.children and parent.children[0].type == 'command_name':

                            # Allow magic numbers in sleep command
                            if self.get_text(parent.children[0]) == 'sleep':
                                is_magic = True

                    # Analyze math comparison contexts
                    elif parent.type == 'binary_expression':
                        comparison_types = COMPARISON_OPS + ('test_operator', 'word')
                        for c in parent.children:
                            if c.type in comparison_types:
                                op_text = self.get_text(c)
                                if op_text in COMPARISON_OPS:
                                    is_magic = True
                                    break

                if is_magic:
                    self.add_issue(line_num, f"NOTICE: Magic number '{val}' detected in logic/sleep. Consider extracting to named constant.")
        self.generic_visit(node)

    def visit_file_redirect(self, node):
        """Inspect file redirect node"""
        line_num = node.start_point[0] + 1

        op_node = None
        target_node = None

        # Extract redirection operator and target from components
        for i, c in enumerate(node.children):
            if c.type in REDIR_OPS_ALL:
                op_node = c
                if i + 1 < len(node.children):
                    target_node = node.children[i + 1]
                break

        # Reject non-POSIX redirection syntax
        if op_node and op_node.type == '&>':
            self.add_issue(line_num, "STYLE: Non-POSIX redirection '&>' detected. Use explicit '> file 2>&1' instead.")

        # Reject non-POSIX target syntax
        elif op_node and op_node.type == '>&' and target_node and target_node.type != 'number':
            self.add_issue(line_num, "STYLE: Non-POSIX redirection '>&' detected. Use explicit '> file 2>&1' instead.")

        # Enforce spacing around redirection operators
        if op_node and target_node and op_node.type in REDIR_OPS_SPACING:
            if target_node.type != 'string' and op_node.end_byte == target_node.start_byte:
                if self.strict:
                    op_text = self.get_text(op_node)
                    tgt_text = self.get_text(target_node)
                    actual_text = self.get_text(node)
                    expected_text = actual_text.replace(f"{op_text}{tgt_text}", f"{op_text} {tgt_text}", 1)
                    self.add_issue(line_num, f"STYLE: Inconsistent redirection spacing. Use '{expected_text}' instead of '{actual_text}'.")
        self.generic_visit(node)


def _check_lexical_formatting(orig_lines, strict, info, issues, multiline_string_lines=None):
    """Evaluate line-based formatting rules"""
    if multiline_string_lines is None:
        multiline_string_lines = set()
    consecutive_empty_lines = 0
    assignment_block = []
    assignment_lines = []
    last_assignment_line = -2

    in_heredoc_block = False
    heredoc_delimiter = ""
    heredoc_allow_indent = False
    has_shebang = False

    header_block_ranges = []
    in_block_start = -1
    for i, l in enumerate(orig_lines):
        s = l.strip()
        if s.startswith('#####') and len(s) == HEADER_TARGET_WIDTH:
            if in_block_start == -1:
                in_block_start = i + 1
            else:
                header_block_ranges.append((in_block_start, i + 1))
                in_block_start = -1

    for i, line in enumerate(orig_lines):
        line_num = i + 1
        stripped = line.strip()

        if line_num == 1 and line.startswith('#!'):
            has_shebang = True
        if strict and line_num == 2 and has_shebang and stripped != '':
            issues[line_num].append("FORMAT: Empty line required after shebang.")

        m = RE_HEREDOC_START.search(line)

        # Track heredoc block boundaries to bypass certain formatting checks
        if not in_heredoc_block and m:
            in_heredoc_block = True
            heredoc_allow_indent = bool(m.group(1) == '-')
            heredoc_delimiter = m.group(2)
        elif in_heredoc_block:
            if (heredoc_allow_indent and stripped == heredoc_delimiter) or (not heredoc_allow_indent and line.rstrip('\n') == heredoc_delimiter):
                in_heredoc_block = False
            elif line.rstrip('\n').startswith(heredoc_delimiter) and len(line.rstrip('\n')) > len(heredoc_delimiter):
                issues[line_num].append("FORMAT: Heredoc termination marker must be on its own line.")

        line_no_comment = RE_LINE_COMMENT_STRIP.sub('', line)

        # Enforce line length limits while exempting logs and URLs
        if strict and not in_heredoc_block and line_num not in multiline_string_lines:
            if len(line_no_comment) > HEADER_TARGET_WIDTH and not stripped.startswith('#'):
                if not any(k in line for k in EXEMPTION_KEYWORDS):
                    if not any(stripped.startswith(cmd) for cmd in LOGGING_COMMANDS):
                        if len(line_no_comment.strip().split(' ')) > 1:

                            # Bypass line length checks for long string or array assignments
                            if not RE_LONG_ASSIGNMENT.match(line):
                                issues[line_num].append(f"FORMAT: Code line exceeds {HEADER_TARGET_WIDTH} characters. Wrap long logic across multiple lines.")

        # Enforce exact header block formatting
        in_header_block = any(start < line_num < end for start, end in header_block_ranges)
        if strict:
            if stripped.startswith('#####') and len(stripped) == HEADER_TARGET_WIDTH:
                pass
            elif stripped.startswith('#####') and len(stripped) != HEADER_TARGET_WIDTH:
                pass
            elif in_header_block:
                if not stripped.startswith('# '):
                    issues[line_num].append("STYLE: Lines inside header block must begin with '# '.")

        # Reject trailing whitespace
        if line.endswith(' ') or line.endswith('\t'):
            if RE_TRAILING_WHITESPACE_BACKSLASH.search(line):
                issues[line_num].append("FORMAT: Trailing whitespace after line-continuation backslash.")
            else:
                issues[line_num].append("FORMAT: Trailing whitespace detected.")

        # Reject trailing semicolons
        if strict and stripped.endswith(';') and not stripped.endswith(';;'):
            issues[line_num].append("STYLE: Unnecessary trailing semicolon. In Bash, newlines act as command terminators.")

        # Process empty lines
        if stripped == '':
            consecutive_empty_lines += 1

            # Validate alphabetical sorting of finalized assignment blocks
            if assignment_block:
                if strict and len(assignment_block) > 1:
                    names = [b[0].casefold() for b in assignment_block]
                    is_dependent = False
                    for idx, (_, _, content) in enumerate(assignment_block):

                        # Bypass sorting requirement if positional arguments are used
                        if RE_POSITIONAL_ARG.search(content):
                            is_dependent = True
                            break

                        # Detect dependency on previously assigned variables in block
                        for earlier_var, _, _ in assignment_block[:idx]:
                            if re.search(rf'\$\{{?{re.escape(earlier_var)}\b', content):
                                is_dependent = True
                                break
                        if is_dependent:
                            break

                    if not is_dependent and names != sorted(names):
                        first_ln = assignment_lines[0]
                        issues[first_ln].append(f"STYLE: Variable assignment block is not alphabetically sorted (starts with '{assignment_block[0][0]}').")
                assignment_block = []
                assignment_lines = []
        else:

            # Enforce vertical spacing rules for blocks and headers
            if consecutive_empty_lines > 1:
                if stripped.startswith('#####'):
                    if consecutive_empty_lines > 2:
                        issues[line_num].append("FORMAT: Header block must be preceded by 1 or 2 empty lines.")
                elif not stripped.startswith('#'):
                    if strict:
                        issues[line_num].append("FORMAT: Too many empty lines. Use single empty line to separate structural blocks.")

            # Track variable assignment blocks
            stripped_no_strings = RE_STRINGS.sub('', stripped)
            is_cmd_with_env = not RE_DECL_PREFIX.match(stripped) and RE_CMD_ENV.search(stripped_no_strings)

            assign_match = RE_ASSIGN_MATCH.match(stripped)
            if assign_match and not is_cmd_with_env:

                # Enforce empty line between variable assignment sets
                if strict and line_num == last_assignment_line + 2 and orig_lines[line_num - 2].strip() == '':
                    issues[line_num].append("STYLE: Empty line between variable assignment sets. Consider grouping them or adding comment.")
                last_assignment_line = line_num

                # Check if there are multiple assignments on this single line
                line_vars = RE_LINE_VARS.findall(stripped)

                # Validate alphabetical sorting of declaration lists
                if strict and len(line_vars) > 1 and RE_DECL_PREFIX.match(stripped):
                    line_vars_lower = [v.casefold() for v in line_vars]
                    if line_vars_lower != sorted(line_vars_lower):
                        issues[line_num].append(f"STYLE: Variables in declaration list '{' '.join(line_vars)}' are not alphabetically sorted.")

                var_name = assign_match.group(1)
                assignment_block.append((var_name, line_num, stripped))
                assignment_lines.append(line_num)
            else:

                # Validate finalized assignment block sorting
                if assignment_block:
                    if strict and len(assignment_block) > 1:
                        names = [b[0].casefold() for b in assignment_block]
                        is_dependent = False
                        for idx, (_, _, content) in enumerate(assignment_block):

                            # Bypass sorting requirement if positional arguments are used
                            if RE_POSITIONAL_ARG.search(content):
                                is_dependent = True
                                break

                            # Detect dependency on previously assigned variables in block
                            for earlier_var, _, _ in assignment_block[:idx]:
                                if re.search(rf'\$\{{?{re.escape(earlier_var)}\b', content):
                                    is_dependent = True
                                    break
                            if is_dependent:
                                break

                        if not is_dependent and names != sorted(names):
                            first_ln = assignment_lines[0]
                            issues[first_ln].append(f"STYLE: Variable assignment block is not alphabetically sorted (starts with '{assignment_block[0][0]}').")
                    assignment_block = []
                    assignment_lines = []

            consecutive_empty_lines = 0

        # Enforce line wrapping after operator
        stripped_no_slash = stripped.rstrip('\\').strip()
        if stripped_no_slash.endswith('|') or stripped_no_slash.endswith('&&') or stripped_no_slash.endswith('||'):
            issues[line_num].append("FORMAT: Line wrapped after operator. Operators must appear at beginning of next line.")

        # Validate math block spacing
        missing_math_start = bool(RE_MATH_START_SPACING.search(line))
        missing_math_end = bool(RE_MATH_END_SPACING.search(line)) and '((' in line

        if strict:
            if missing_math_start and missing_math_end:
                issues[line_num].append("FORMAT: Missing spaces inside math block: use '(( ... ))' or '$(( ... ))'.")
            elif missing_math_start:
                issues[line_num].append("FORMAT: Missing space after math start: use '(( ... ))' or '$(( ... ))'.")
            elif missing_math_end:
                issues[line_num].append("FORMAT: Missing space before math end: use '(( ... ))' or '$(( ... ))'.")

        # Recommend Bash arithmetic evaluation for increments
        if info:
            if RE_MATH_INCREMENT.search(line):
                issues[line_num].append("NOTICE: Use Bash arithmetic evaluation '(( count++ ))' or '(( count-- ))' for cleaner increments.")

    # Validate alphabetical sorting of finalized assignment blocks at end of file
    if strict and assignment_block:
        if len(assignment_block) > 1:
            names = [b[0].casefold() for b in assignment_block]
            is_dependent = False
            for idx, (_, _, content) in enumerate(assignment_block):

                # Bypass sorting requirement if positional arguments are used
                if RE_POSITIONAL_ARG.search(content):
                    is_dependent = True
                    break

                # Detect dependency on previously assigned variables in block
                for earlier_var, _, _ in assignment_block[:idx]:
                    if re.search(rf'\$\{{?{re.escape(earlier_var)}\b', content):
                        is_dependent = True
                        break
                if is_dependent:
                    break

            if not is_dependent and names != sorted(names):
                first_ln = assignment_lines[0]
                issues[first_ln].append(f"STYLE: Variable assignment block is not alphabetically sorted (starts with '{assignment_block[0][0]}').")


def check_format(filepath, strict=False, info=False, force_sh=False, stdin_content=None):
    """Run styling, formatting, and structural checks on script"""
    if TS_PARSER is None:
        raise DependencyError("'tree-sitter' or 'tree-sitter-bash' not found. Please install them to run this linter.")

    if filepath != '-' and not os.path.exists(filepath):
        print(f"Error: File {filepath} not found", file=sys.stderr)
        return None

    issues = defaultdict(list)

    # Pass standard input to external tools
    if filepath == '-':
        raw_data = stdin_content
    else:
        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
        except FileNotFoundError:
            return None

    try:
        text = raw_data.decode('utf-8')
    except UnicodeDecodeError:
        print(f"Error: File {filepath} is not valid UTF-8 text.", file=sys.stderr)
        return None

    # Reject DOS line endings
    if b'\r\n' in raw_data:
        issues[0] = issues.get(0, []) + ["FORMAT: File uses CRLF line endings. Convert to LF."]

    orig_lines = text.splitlines()

    # Parse AST with tree-sitter
    try:
        tree = TS_PARSER.parse(raw_data)
        _ast_cache[filepath] = (raw_data, tree)
        visitor = FormatVisitor(raw_data, filepath, orig_lines, strict, info)
        visitor.visit(tree.root_node)

        # Evaluate unassigned readonly variables
        for var_name, ln in visitor.naked_readonly_candidates:
            if var_name not in visitor.initialized_vars:
                issues[ln].append("STYLE: Naked readonly declaration leaves intention unclear. Assign and declare 'readonly var=val' on same line.")

        # Aggregate visitor issues into main issue tracker
        for ln, msgs in visitor.issues.items():
            issues[ln].extend(msgs)

        _check_lexical_formatting(orig_lines, strict, info, issues, visitor.multiline_string_lines)

        # Validate global strict mode
        if not (visitor.has_errexit and visitor.has_nounset and (visitor.has_pipefail or visitor.is_sh_script)):
            missing = []
            if not visitor.has_errexit:
                missing.append('errexit (-e)')
            if not visitor.has_nounset:
                missing.append('nounset (-u)')
            if not visitor.has_pipefail and not visitor.is_sh_script:
                missing.append('pipefail')

            issues[0] = issues.get(0, []) + [
                f"SAFETY: Missing strict mode declarations. Expected: {', '.join(missing)}."
            ]

        # Enforce truncation protection via main wrapper
        if not visitor.has_main_wrapper and not visitor.is_sh_script:
            issues[0] = issues.get(0, []) + [
                "SAFETY: No main() wrapper detected. Wrap execution logic in 'main' and call it at end of file to protect against curl-pipe truncation."
            ]

        # Cross-reference uppercase assignments with standalone readonly/export modifiers
        for var_name, line_num in visitor.uppercase_assignments:
            if var_name not in visitor.standalone_modifiers['readonly'] and var_name not in visitor.standalone_modifiers['export']:
                if info:
                    issues[line_num].append(f"NOTICE: Variable '{var_name}' is UPPERCASE but lacks 'readonly' modifier. Consider adding 'readonly' if it is constant, or use lowercase.")

    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        print(f"Error parsing AST in {filepath}: {e}", file=sys.stderr)

    # Execute ShellCheck
    try:
        sc_args = list(SHELLCHECK_BASE_ARGS)
        if force_sh:
            sc_args.append('--shell=sh')

        # Traverse directory tree to locate nearest .shellcheckrc
        script_dir = os.path.dirname(os.path.abspath(filepath))
        has_rc = False
        curr_dir = script_dir
        while True:
            if os.path.exists(os.path.join(curr_dir, '.shellcheckrc')) or os.path.exists(os.path.join(curr_dir, 'shellcheckrc')):
                has_rc = True
                break
            parent = os.path.dirname(curr_dir)
            if parent == curr_dir:
                break
            curr_dir = parent

        if not has_rc and (os.path.exists('.shellcheckrc') or os.path.exists('shellcheckrc')):
            has_rc = True

        if not has_rc and os.path.exists(os.path.expanduser('~/.shellcheckrc')):
            has_rc = True

        # Apply comprehensive style checks if no custom config exists
        if not has_rc:
            sc_args.extend(SHELLCHECK_EXTRA_OPTS)

        sc_args.append(filepath)

        kwargs = {'capture_output': True, 'text': True}
        if filepath == '-':
            kwargs['input'] = stdin_content.decode('utf-8')

        sc_result = subprocess.run(sc_args, check=False, **kwargs)

        # Parse ShellCheck gcc output format
        for sc_line in sc_result.stdout.splitlines():
            m = RE_SHELLCHECK_OUTPUT.match(sc_line)
            if m:
                ln = int(m.group(1))
                msg = m.group(3)
                sev = m.group(2).upper()

                sc_ignore = False

                # Suppress subjective or duplicated ShellCheck rules
                for pat in SHELLCHECK_FUZZY_PATTERNS:
                    if re.search(pat, msg):
                        sc_ignore = True
                        break

                if sc_ignore:
                    continue

                if '[SC2250]' in msg:
                    continue

                # Deduplicate identical ShellCheck codes on same line
                sc_code_match = RE_SHELLCHECK_CODE.search(msg)
                if sc_code_match:
                    sc_code = sc_code_match.group(1)
                    if any(f"[{sc_code}]" in existing for existing in issues[ln]):
                        continue

                issues[ln].append(f"SHELLCHECK {sev}: {msg}")
    except FileNotFoundError as exc:
        raise DependencyError("'shellcheck' binary not found. Please install ShellCheck to run this linter.") from exc

    # Run structural checks with shfmt
    try:
        sf_args = list(SHFMT_BASE_ARGS)
        if force_sh:
            sf_args.append('--posix')
        sf_args.append(filepath)
        kwargs = {'capture_output': True, 'text': True}
        if filepath == '-':
            kwargs['input'] = stdin_content.decode('utf-8')

        sf_result = subprocess.run(sf_args, check=False, **kwargs)
        diff_lines = sf_result.stdout.splitlines()

        current_line = 0
        old_buffer, new_buffer = [], []

        def flush_buffers():
            """Synchronize buffers and flush shfmt formatting results"""
            def clean_for_match(s):
                """Clean bash syntax structure to match diff accurately"""
                s = s.strip()
                s = RE_CLEAN_DIFF_PREFIX.sub('', s)
                s = RE_CLEAN_DIFF_SUFFIX.sub('', s)
                return RE_CLEAN_DIFF_SPACE.sub('', s)

            new_buffer_consumed = [False] * len(new_buffer)

            for old_text, ln in old_buffer:
                old_stripped = old_text.strip()

                # Exclude comments and empty lines from structural diff comparison
                if not old_stripped or old_stripped.startswith('#'):
                    continue

                old_clean = clean_for_match(old_text)

                # Ignore heavily scrubbed lines in diff to prevent false positives
                if not old_clean:
                    continue

                matched_idx = -1
                for idx, n in enumerate(new_buffer):

                    # Identify exact logical match across diff boundaries
                    if not new_buffer_consumed[idx] and clean_for_match(n) == old_clean:
                        matched_idx = idx
                        break

                # Process matching lines in diff buffers
                if matched_idx != -1:
                    new_buffer_consumed[matched_idx] = True
                    new_text = new_buffer[matched_idx]
                    old_indent = len(old_text) - len(old_text.lstrip())
                    new_indent = len(new_text) - len(new_text.lstrip())

                    # Flag indentation mismatch between source and shfmt
                    if old_indent != new_indent:
                        issues[ln].append(
                            f"SHFMT: Structural mismatch (expected {new_indent} spaces, "
                            f"got {old_indent})"
                        )

            old_buffer.clear()
            new_buffer.clear()

        # Parse raw shfmt diff line-by-line
        for line in diff_lines:
            if line.startswith('---') or line.startswith('+++'):
                continue

            # Parse diff hunk header to track line numbers
            if line.startswith('@@'):
                flush_buffers()
                m = RE_DIFF_HUNK_START.search(line)
                if m:
                    current_line = int(m.group(1)) - 1
                continue

            if line.startswith(' '):
                flush_buffers()
                current_line += 1

            # Buffer removed lines for formatting comparison
            elif line.startswith('-'):
                old_buffer.append((line[1:], current_line + 1))
                current_line += 1

            # Buffer added lines for formatting comparison
            elif line.startswith('+'):
                new_buffer.append(line[1:])

        flush_buffers()

    except FileNotFoundError as exc:
        raise DependencyError("'shfmt' binary not found. Please install shfmt to run this linter.") from exc

    # Deduplicate warnings
    for ln, msgs in issues.items():

        has_style_indent = any(RE_STYLE_INDENT_MSG.match(m) for m in msgs)
        if has_style_indent:
            msgs = [m for m in msgs if not m.startswith("SHFMT: Structural mismatch")]

        has_style_bracket = any("Use Bash keyword '[[ ... ]]'" in m for m in msgs)
        if has_style_bracket:
            msgs = [m for m in msgs if "[SC2292]" not in m]

        issues[ln] = msgs

    return issues


def analyze_dead_code(target_scripts, stdin_content=None):
    """Cross-reference function calls and variable expansions across files"""
    global_funcs = {}
    global_vars = {}
    all_words = []
    all_var_usages = []

    # Parse target scripts to build global maps
    for filepath in target_scripts:
        if filepath != '-' and not os.path.exists(filepath):
            continue

        if filepath in _ast_cache:
            raw_data, tree = _ast_cache[filepath]
        else:
            if filepath == '-':
                raw_data = stdin_content
            else:
                with open(filepath, 'rb') as f:
                    raw_data = f.read()

            try:
                tree = TS_PARSER.parse(raw_data)
            except Exception:
                continue

        # Extract symbols via dedicated visitor
        visitor = DeadCodeVisitor(raw_data, filepath)
        visitor.visit(tree.root_node)

        for k, v in visitor.global_funcs.items():
            if k not in global_funcs:
                global_funcs[k] = []
            global_funcs[k].extend(v)

        for k, v in visitor.global_vars.items():
            if k not in global_vars:
                global_vars[k] = []
            global_vars[k].extend(v)

        all_words.extend(visitor.all_words)
        all_var_usages.extend(visitor.all_var_usages)

    dead_issues = {fp: defaultdict(list) for fp in target_scripts if fp == '-' or os.path.exists(fp)}

    # Count occurrences to find unused symbols
    word_counts = Counter(all_words)
    var_counts = Counter(all_var_usages)

    # Flag uninvoked functions
    for func_name, locations in global_funcs.items():
        if word_counts[func_name] <= 1:
            for fp, ln in locations:
                dead_issues[fp][ln].append(
                    f"DEAD CODE: Function '{func_name}' is defined but never invoked."
                )

    # Flag unused global variables
    for var_name, locations in global_vars.items():
        if var_counts[var_name] == 0:
            if var_name not in IGNORED_UNUSED_VARIABLES and var_name not in INTENTIONAL_GLOBALS and var_name not in STANDARD_ENV_VARIABLES:
                for fp, ln in locations:
                    dead_issues[fp][ln].append(
                        f"DEAD CODE: Global variable '{var_name}' is assigned but never used."
                    )

    return dead_issues


# Execute main program
if __name__ == '__main__':
    args = sys.argv[1:]

    if not args or '--help' in args or '-h' in args:
        print(USAGE_MSG)
        sys.exit(0 if args else 1)

    if '--version' in args or '-v' in args:
        print(f"Shellens v{__version__}")
        sys.exit(0)

    use_markdown = False
    use_strict = False
    use_info = False
    force_sh = False
    use_no_color = not sys.stdout.isatty() or os.environ.get('NO_COLOR')
    target_scripts = []

    args_iter = iter(args)
    for arg in args_iter:
        if arg == '--':
            target_scripts.extend(list(args_iter))
            break

        if arg == '--markdown':
            use_markdown = True
        elif arg == '--strict':
            use_strict = True
        elif arg == '--info':
            use_info = True
        elif arg == '--sh':
            force_sh = True
        elif arg == '--no-color':
            use_no_color = True

        elif arg.startswith('-') and arg != '-':
            print(f"Error: Unknown option '{arg}'", file=sys.stderr)
            print(USAGE_MSG, file=sys.stderr)
            sys.exit(1)

        else:

            # Collect and glob script targets
            matches = glob.glob(arg, recursive=True)
            if matches and arg != '-':
                for match in matches:
                    if os.path.isdir(match):
                        for root, dirs, files in os.walk(match):

                            # Skip hidden directories and node_modules
                            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
                            for f in files:
                                path = os.path.join(root, f)
                                if path.endswith(('.sh', '.bash')):
                                    target_scripts.append(path)
                                else:
                                    try:
                                        with open(path, 'rb') as file_obj:
                                            first_line = file_obj.readline()
                                            if first_line.startswith(b'#!') and (b'sh' in first_line or b'bash' in first_line):
                                                target_scripts.append(path)
                                    except Exception:
                                        pass

                    else:
                        target_scripts.append(match)
            else:
                target_scripts.append(arg)

    # Deduplicate script targets while preserving order
    target_scripts = list(dict.fromkeys(target_scripts))

    # Strip colors if no color flag is set or markdown output is selected
    if use_no_color or use_markdown:
        C_RESET = C_BOLD = C_RED = C_YELLOW = C_CYAN = C_BLUE = C_DIM = ''

    if not target_scripts:
        print("Error: No script paths provided", file=sys.stderr)
        sys.exit(1)

    has_missing_files = False

    # Validate target scripts existence and readability
    for script in target_scripts:
        if script == '-':
            continue

        # Reject missing files
        if not os.path.exists(script):
            print(f"Error: File {script} not found", file=sys.stderr)
            has_missing_files = True

        # Reject directories and special files
        elif not os.path.isfile(script):
            print(f"Error: Path {script} is not regular file", file=sys.stderr)
            has_missing_files = True

        # Reject files without read permissions
        elif not os.access(script, os.R_OK):
            print(f"Error: File {script} is not readable (Permission Denied)", file=sys.stderr)
            has_missing_files = True

    if has_missing_files:
        sys.exit(1)

    stdin_content = None

    # Initialize raw input data for stdin processing
    if '-' in target_scripts:
        stdin_content = sys.stdin.read().encode('utf-8')

    all_issues = defaultdict(list)

    # Run check_format on all target scripts
    try:
        for script in target_scripts:
            result = check_format(script, strict=use_strict, info=use_info, force_sh=force_sh, stdin_content=stdin_content)

            if result is not None:
                all_issues[script] = result
            else:
                sys.exit(1)

        dead_code_issues = analyze_dead_code(target_scripts, stdin_content=stdin_content)
    except DependencyError as e:
        print(f"CRITICAL ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    total_project_issues = 0

    # Aggregate issues and generate reports
    for script in target_scripts:
        issues = all_issues.get(script, {})
        dead_issues = dead_code_issues.get(script, {})

        for ln, msgs in dead_issues.items():
            issues[ln].extend(msgs)

        script_total = sum(len(msgs) for msgs in issues.values())
        total_project_issues += script_total

        if script_total == 0:
            print(f"Perfect! No formatting, style, or dead code issues found in {script}")
            continue

        script_display_name = "<stdin>" if script == '-' else script
        script_name_base = "stdin" if script == '-' else os.path.basename(script).replace('.', '-')

        if use_markdown:

            # Generate markdown report
            md_filename = f"{script_name_base}-report.md"
            with open(md_filename, 'w', encoding='utf-8') as f:
                f.write(f"# Analysis Report: `{script_display_name}`\n\n*Generated by Shellens*\n\n")
                f.write(f"**Total Issues:** {script_total}\n\n")
                f.write("| Line | Category | Message |\n")
                f.write("| :--- | :--- | :--- |\n")

                for ln in sorted(issues.keys()):
                    if not issues[ln]:
                        continue
                    line_str = "Global" if ln == 0 else str(ln)

                    for msg in issues[ln]:
                        parts = msg.split(': ', 1)
                        cat = parts[0]
                        desc = parts[1] if len(parts) > 1 else ""

                        # Escape markdown special characters
                        safe_desc = desc.replace('|', '&#124;').replace('\n', ' ')
                        safe_desc = safe_desc.replace('$', '&#36;').replace('_', '&#95;')
                        safe_desc = safe_desc.replace('*', '&#42;')

                        # Append ShellCheck wiki link
                        if 'SHELLCHECK' in cat:
                            sc_match = RE_SHELLCHECK_CODE.search(safe_desc)
                            if sc_match:
                                sc_code = sc_match.group(1)
                                safe_desc = re.sub(
                                    rf'\[{sc_code}\]',
                                    f'[[{sc_code}]](https://www.shellcheck.net/wiki/{sc_code})',
                                    safe_desc
                                )

                        f.write(f"| {line_str} | `{cat}` | {safe_desc} |\n")

            print(f"Markdown report generated: {md_filename}")
        else:

            # Print formatted terminal report
            print(f"{C_BOLD}================================================================================{C_RESET}")
            print(f"{C_BOLD} ANALYSIS REPORT: {script_display_name} (Generated by Shellens){C_RESET}")
            print(f"{C_BOLD}================================================================================{C_RESET}")
            print(f" Total Issues: {script_total}")
            print(f"{C_BOLD}--------------------------------------------------------------------------------{C_RESET}")

            for ln in sorted(issues.keys()):
                if not issues[ln]:
                    continue

                print()
                if ln == 0:
                    print(f"{C_BOLD}GLOBAL ISSUES{C_RESET}")
                else:
                    print(f"{C_DIM}Line {ln:04d}{C_RESET}")

                for msg in issues[ln]:
                    parts = msg.split(': ', 1)
                    cat = parts[0]
                    desc = parts[1] if len(parts) > 1 else ""

                    cat_color = get_color(cat)
                    padded_cat = f"[{cat}]".ljust(20)

                    print(f"  {cat_color}{padded_cat}{C_RESET} {desc}")
            print()

    # Exit with status 1 on error in terminal mode
    if (total_project_issues > 0 or has_missing_files) and not use_markdown:
        sys.exit(1)
