#!/usr/bin/env python3

"""
==============================================================================
LEGACY REGEX ENGINE (shellens_regex.py)
==============================================================================
This is the original v0.x Regular Expression-based parsing engine for Shellens.
It is preserved for historical reference and benchmarking.

Known Architectural Limitations:
- Regex cannot natively understand Bash AST, requiring brittle state-trackers
  (quote_stacks, conditional_depths).
- Fails on variables expanded inside quoted heredocs (`<< 'EOF'`).
- Bypasses dead code tracking for global variables declared via `declare` or `typeset`.

The active engine in `shellens.py` uses true AST parsing.
==============================================================================

Shellens: A Better Linter for Bash and Shell

Enforces strict architectural philosophy, defensive programming, POSIX
compliance, predictable formatting, and visual hierarchy across shell environments
"""

import glob
import os
import re
import subprocess
import sys
from collections import Counter


################################################################################
# Constants
################################################################################

__version__ = "0.9.0"

# ANSI Colors
C_BLUE = '\033[94m'
C_BOLD = '\033[1m'
C_CYAN = '\033[96m'
C_DIM = '\033[2m'
C_RED = '\033[91m'
C_RESET = '\033[0m'
C_YELLOW = '\033[93m'

# Exemptions
INTENTIONAL_GLOBALS = ('verbosity',)
STANDARD_ENV_VARS = (
    'EUID', 'FUNCNAME', 'IFS', 'LC_ALL', 'OPTARG', 'OPTIND',
    'PATH', 'PPID', 'PWD', 'REPLY', 'SECONDS', 'TZ', 'USER'
)


################################################################################
# Helper Functions
################################################################################

def get_color(category):
    """
    Return appropriate ANSI color code based on issue category
    """
    if category in ('SAFETY', 'WARNING', 'SHELLCHECK ERROR', 'SHELLCHECK WARNING'):
        return C_RED
    if category in ('DEAD CODE', 'SCOPE'):
        return C_YELLOW
    if category in ('COMPLEXITY', 'NOTICE'):
        return C_CYAN
    if category in ('STYLE', 'SHFMT', 'SHELLCHECK STYLE', 'SHELLCHECK INFO'):
        return C_BLUE
    return C_RESET


def analyze_dead_code(filepaths, stdin_content=None):
    """
    Cross-reference function calls and variable expansions across files
    """
    global_funcs = {}
    global_vars = {}

    all_words = []
    all_var_usages = []

    for filepath in filepaths:
        if filepath != '-' and not os.path.exists(filepath):
            continue

        if filepath == '-':
            lines = stdin_content.decode('utf-8').splitlines()
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()

        full_text = "\n".join(lines)

        # Remove function definitions to avoid counting them as usages
        text_without_func_defs = re.sub(
            r'^\s*(?:function\s+)?([a-zA-Z0-9_]+)\s*\(\)',
            '',
            full_text,
            flags=re.MULTILINE
        )
        all_words.extend(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', text_without_func_defs))

        # Find all variable expansions
        all_var_usages.extend(re.findall(r'\$([a-zA-Z_][a-zA-Z0-9_]*)\b', full_text))
        all_var_usages.extend(re.findall(r'\$\{(?:#|!)?([a-zA-Z_][a-zA-Z0-9_]*)[^}]*\}', full_text))

        # Find bare variables inside math contexts
        for math_match in re.finditer(r'\(\((.+?)\)\)', full_text):
            inner_math = math_match.group(1)
            all_var_usages.extend(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', inner_math))

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.lstrip()

            if stripped.startswith('#'):
                continue

            # Global function definitions
            func_match = re.match(r'^\s*(?:function\s+)?([a-zA-Z0-9_]+)\s*\(\)', line)
            if func_match:
                global_funcs[func_match.group(1)] = (filepath, line_num)

            # Global variable assignments
            if not re.match(r'^\s*local\s+', line):
                assign_match = re.match(
                    r'^\s*(?:export\s+|readonly\s+)?([a-zA-Z_][a-zA-Z0-9_]*)(?:\[.*\])?\+?=(?!=)',
                    line
                )
                if assign_match:
                    global_vars[assign_match.group(1)] = (filepath, line_num)

    dead_issues = {fp: {} for fp in filepaths if fp == '-' or os.path.exists(fp)}

    word_counts = Counter(all_words)
    var_counts = Counter(all_var_usages)

    for func_name, (fp, ln) in global_funcs.items():
        if word_counts[func_name] == 0:
            if ln not in dead_issues[fp]:
                dead_issues[fp][ln] = []
            dead_issues[fp][ln].append(
                f"DEAD CODE: Function '{func_name}' is defined but never invoked."
            )

    for var_name, (fp, ln) in global_vars.items():
        if var_counts[var_name] == 0:

            # Ignore conventional unused vars or bash internals
            if var_name not in ('_', 'dummy', 'i', 'line', 'item', 'IFS', 'OPTARG', 'OPTIND', 'REPLY'):
                if ln not in dead_issues[fp]:
                    dead_issues[fp][ln] = []
                dead_issues[fp][ln].append(
                    f"DEAD CODE: Global variable '{var_name}' is assigned but never used."
                )

    return dead_issues


################################################################################
# Core Formatting Checks
################################################################################

def check_format(filepath, verbose=False, force_sh=False, stdin_content=None):
    """
    Run styling, formatting, and structural checks on given Bash script
    """
    if filepath != '-' and not os.path.exists(filepath):
        print(f"Error: File {filepath} not found")
        return None

    issues = {}

    # Check line endings
    if filepath == '-':
        raw_data = stdin_content
    else:
        with open(filepath, 'rb') as f:
            raw_data = f.read()

    if b'\r\n' in raw_data:
        issues[0] = ["GLOBAL: File uses CRLF (Windows) line endings instead of LF."]

    try:
        orig_lines = raw_data.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        print(f"Error: File {filepath} is not valid UTF-8 text.")
        return None

    first_line = orig_lines[0] if orig_lines else ""
    is_sh_script = force_sh or bool(re.match(r'^#!\s*(?:/usr/bin/env\s+)?(?:/bin/|/usr/bin/)?(?:sh|dash|ash)\b', first_line.strip()))

    # State variables
    in_heredoc = False
    heredoc_delim = ""
    heredoc_dash = False
    quote_stack = []
    in_function = False
    current_func_name = ""
    current_func_line = 0
    func_complexity = 1
    current_func_exec_lines = 0
    code_since_last_comment = True
    empty_count = 0
    in_comment_block = False
    in_header_block = False
    conditional_depth = 0

    # Strict mode tracking
    has_errexit = False
    has_nounset = False
    has_pipefail = False

    local_vars_in_func = set()
    in_local_decl_block = False
    has_seen_code = False
    prev_line_had_inline_comment = False

    def is_line_continuation(text):
        """
        Check if string ends with unescaped line continuation backslash
        """
        safe_text = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', text)
        if re.search(r'(?<!\\)(?:^|\s)#', safe_text):
            return False
        stripped = text.rstrip('\\')
        return (len(text) - len(stripped)) % 2 == 1

    # Build logical lines for standalone modifier tracking and later checks
    logical_lines = []
    current_log_line = ""
    start_ln = 0
    for i, line in enumerate(orig_lines):
        if not current_log_line:
            start_ln = i + 1
        if is_line_continuation(line.rstrip('\r\n ')):
            current_log_line += line.rstrip('\r\n ')[:-1] + " "
        else:
            current_log_line += line
            logical_lines.append((start_ln, current_log_line))
            current_log_line = ""

    # Pre-parse file to find standalone readonly/export declarations (e.g. `readonly VAR1 VAR2`)
    standalone_modifiers = {'readonly': set(), 'export': set()}
    for ln, log_line in logical_lines:
        safe_line = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', log_line)
        for mod in ('readonly', 'export'):
            if re.match(rf'^\s*{mod}\b', safe_line):
                for v in safe_line.replace(mod, '', 1).split():
                    if '=' not in v and not v.startswith('-'):
                        standalone_modifiers[mod].add(v)

    # Custom styling rules
    for i, line in enumerate(orig_lines):
        line_num = i + 1
        stripped = line.lstrip()
        is_empty = not stripped
        started_in_string = bool(quote_stack)

        if line_num not in issues:
            issues[line_num] = []

        # Flag trailing whitespace
        if line.rstrip() != line:
            issues[line_num].append("STYLE: Trailing whitespace.")

        # Track heredocs
        if in_heredoc:
            close_candidate = line.lstrip('\t') if heredoc_dash else line
            if close_candidate.rstrip('\r\n ') == heredoc_delim:
                in_heredoc = False
            elif re.match(rf'^{re.escape(heredoc_delim)}\b', close_candidate):
                issues[line_num].append(
                    f"STYLE: Heredoc termination marker '{heredoc_delim}' must be on its own line. "
                    "Trailing characters detected."
                )

            code_since_last_comment = True
            empty_count = 0
            continue

        if is_empty:
            empty_count += 1
            in_comment_block = False
            in_header_block = False
            prev_line_had_inline_comment = False
            continue

        m = re.search(r'<<\s*([-]?)\s*[\'"]?([a-zA-Z0-9_-]+)[\'"]?', line)
        if m:
            in_heredoc = True
            heredoc_dash = m.group(1) == '-'
            heredoc_delim = m.group(2)

        # Enforce comment block rules and header structures
        is_comment = stripped.startswith('#')
        is_shebang = is_comment and stripped.startswith('#!')
        is_shellcheck_directive = is_comment and re.search(
            r'^#\s*shellcheck\s+(disable|source)=', stripped
        )

        if is_comment and not is_shebang and not is_shellcheck_directive:

            # Validate divider headers
            if stripped.startswith('#####'):
                if len(stripped.rstrip()) != 80 or not all(c == '#' for c in stripped.rstrip()):
                    issues[line_num].append(
                        f"STYLE: Header block must be exactly 80 '#' characters "
                        f"(found {len(stripped.rstrip())})."
                    )

            comment_text = stripped.lstrip('#')
            is_commented_code = '#' in comment_text.strip()

            if not in_comment_block and not is_commented_code:

                if stripped.startswith('#####'):
                    in_header_block = True
                else:
                    in_header_block = False

                # Check preceding empty lines for new comment block
                if has_seen_code:
                    if stripped.startswith('#####'):
                        if i > 0 and empty_count not in (1, 2):
                            issues[line_num].append(
                                f"STYLE: Header block must be preceded by 1 or 2 empty lines "
                                f"(found {empty_count})."
                            )
                    else:
                        if prev_line_had_inline_comment:
                            pass
                        elif i > 0 and empty_count != 1:
                            issues[line_num].append(
                                f"STYLE: Comment must be preceded by exactly one empty line "
                                f"(found {empty_count})."
                            )

                    if not code_since_last_comment and not prev_line_had_inline_comment and not stripped.startswith('#####'):
                        issues[line_num].append(
                            "STYLE: No code between this comment and the previous comment block."
                        )

                in_comment_block = True
                code_since_last_comment = False
            elif is_commented_code:
                in_comment_block = True
                code_since_last_comment = False
            elif in_comment_block:
                if has_seen_code and not in_header_block and not stripped.startswith('#####') and not prev_line_had_inline_comment:
                    issues[line_num].append(
                        "STYLE: Multi-line comments are not allowed unless enclosed in '#####' header blocks. "
                        "Combine into a single line or use separate blocks with code between."
                    )
                code_since_last_comment = False

            empty_count = 0

            # Scan for grammatical articles and trailing periods
            if has_seen_code and not stripped.startswith('#####') and not is_commented_code:

                # Ignore URLs to prevent false positives on paths like '/a/'
                if 'http://' not in comment_text and 'https://' not in comment_text:
                    found_articles = re.findall(r'\b(a|an|the)\b', comment_text, re.IGNORECASE)
                    if found_articles:
                        articles_str = ', '.join(set(a.lower() for a in found_articles))
                        issues[line_num].append(
                            f"STYLE: Comment contains grammatical articles ({articles_str}). "
                            "Use imperative mood without articles."
                        )

                # Catch trailing periods
                stripped_comment = comment_text.rstrip()
                if stripped_comment.endswith('.'):
                    issues[line_num].append(
                        "STYLE: Comment ends with a trailing period. "
                        "Imperative commands should not end with punctuation."
                    )

                # Catch Comment Indentation
                if len(stripped) < 80:
                    next_code_indent = None
                    next_code_line = ""
                    for j in range(i + 1, len(orig_lines)):
                        next_line = orig_lines[j]
                        next_stripped = next_line.lstrip()
                        if next_stripped and not next_stripped.startswith('#'):
                            next_code_indent = len(next_line) - len(next_stripped)
                            next_code_line = next_stripped
                            break

                    comment_indent = len(line) - len(stripped)
                    if next_code_indent is not None and comment_indent != next_code_indent:
                        is_closing_block = re.match(r'^(fi\b|done\b|esac\b|elif\b|else\b|\})', next_code_line)
                        is_valid = False

                        if is_closing_block:
                            prev_code_indent = None
                            for k in range(i - 1, -1, -1):
                                prev_line = orig_lines[k]
                                prev_stripped = prev_line.lstrip()
                                if prev_stripped and not prev_stripped.startswith('#'):
                                    prev_code_indent = len(prev_line) - len(prev_stripped)
                                    break

                            if comment_indent == prev_code_indent:
                                is_valid = True
                            elif comment_indent < next_code_indent:
                                is_valid = True

                        if not is_valid:
                            issues[line_num].append(
                                f"STYLE: Comment indentation mismatch (expected {next_code_indent}, got {comment_indent})."
                            )

                prev_line_had_inline_comment = False

        elif is_shellcheck_directive:
            if has_seen_code and empty_count > 1:
                issues[line_num].append(
                    f"STYLE: Too many empty lines (found {empty_count}, max 1 allowed)."
                )
            in_comment_block = False
            in_header_block = False
            empty_count = 0
            prev_line_had_inline_comment = False

        elif not is_shebang:

            # Process standard code line
            if has_seen_code and empty_count > 1:
                issues[line_num].append(
                    f"STYLE: Too many empty lines (found {empty_count}, max 1 allowed)."
                )
            has_seen_code = True
            in_comment_block = False
            in_header_block = False
            code_since_last_comment = True
            empty_count = 0

            # Detect inline comments
            struct_line_for_inline = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', line)
            prev_line_had_inline_comment = '#' in struct_line_for_inline

            # Detect strict mode declarations
            if not has_errexit and re.search(r'\bset\s+.*-e\b|\bset\s+-.*e.*\b|\bset\s+-o\s+errexit\b', line):
                has_errexit = True
            if not has_nounset and re.search(r'\bset\s+.*-u\b|\bset\s+-.*u.*\b|\bset\s+-o\s+nounset\b', line):
                has_nounset = True
            if not has_pipefail and re.search(r'\bset\s+.*-[a-zA-Z]*o\s+pipefail\b', line):
                has_pipefail = True

        # Enforce 80-character maximum line length
        if len(line) > 80 and 'http://' not in line and 'https://' not in line:
            is_text_line = (
                stripped.startswith('#') or
                stripped.startswith('echo') or
                stripped.startswith('printf') or
                stripped.startswith('log') or
                'osascript' in line or
                bool(quote_stack and quote_stack[-1] in ('"', "'")) or
                in_heredoc
            )

            if is_text_line:
                if verbose:
                    issues[line_num].append(
                        f"STYLE: Text line exceeds 80 characters ({len(line)} chars)."
                    )
            else:

                # Ignore long uninterrupted strings or arrays
                if not re.match(r'^\s*([a-zA-Z0-9_]+(\+?=)?\s*\(?\s*["\']?[^ ]{60,})', line):
                    issues[line_num].append(
                        f"STYLE: Code line exceeds 80 characters ({len(line)} chars)."
                    )

        code_only_chars = []
        struct_line_chars = []
        struct_line_spacing_chars = []

        # State machine to safely strip strings across multiple lines
        global_escape = False
        for idx, c in enumerate(line):
            in_squote = bool(quote_stack and quote_stack[-1] == "'")
            in_ansi_quote = bool(quote_stack and quote_stack[-1] == "$'")
            in_dquote = bool(quote_stack and quote_stack[-1] == '"')

            if global_escape:
                global_escape = False
                if not in_squote and not in_ansi_quote and not in_dquote:
                    code_only_chars.append(c)
                    struct_line_chars.append(c)
                    struct_line_spacing_chars.append(c)
                else:
                    code_only_chars.append(c)
                    struct_line_spacing_chars.append('X')
                continue

            if c == '\\':
                if not in_squote:
                    global_escape = True
                if not in_squote and not in_ansi_quote and not in_dquote:
                    code_only_chars.append(c)
                    struct_line_chars.append(c)
                    struct_line_spacing_chars.append(c)
                else:
                    code_only_chars.append(c)
                    struct_line_spacing_chars.append('X')
                continue

            if c == "'" and not in_dquote:
                if quote_stack and quote_stack[-1] == "'":
                    quote_stack.pop()
                elif quote_stack and quote_stack[-1] == "$'":
                    quote_stack.pop()
                else:
                    if idx > 0 and line[idx-1] == '$':

                        # Push "$'" since $ already processed and appended
                        quote_stack.append("$'")
                    else:
                        quote_stack.append("'")
                code_only_chars.append(c)
                struct_line_spacing_chars.append('X')
                continue

            if c == '"' and not in_squote and not in_ansi_quote:
                if quote_stack and quote_stack[-1] == '"':
                    quote_stack.pop()
                else:
                    quote_stack.append('"')
                code_only_chars.append(c)
                struct_line_spacing_chars.append('X')
                continue

            if c == '$' and idx + 1 < len(line) and line[idx+1] == '(' and not in_squote and not in_ansi_quote:
                quote_stack.append("$(")
                code_only_chars.append(c)
                struct_line_chars.append(c)
                struct_line_spacing_chars.append(c)
                continue

            if c == ')' and quote_stack and quote_stack[-1] == "$(" and not in_squote and not in_ansi_quote and not in_dquote:
                quote_stack.pop()
                code_only_chars.append(c)
                struct_line_chars.append(c)
                struct_line_spacing_chars.append(c)
                continue

            if not in_squote and not in_ansi_quote and not in_dquote:
                if c == '#':
                    if idx == 0 or line[idx-1].isspace():
                        break
                code_only_chars.append(c)
                struct_line_chars.append(c)
                struct_line_spacing_chars.append(c)
            else:
                code_only_chars.append(c)
                struct_line_spacing_chars.append('X')

        global_escape = False

        code_only = "".join(code_only_chars) if not is_comment else ""
        struct_line = "".join(struct_line_chars) if not is_comment else ""
        struct_line_with_spacing = "".join(struct_line_spacing_chars) if not is_comment else ""

        # Flag bare variables
        for m in re.finditer(r'(?<![\$\\])\$([a-zA-Z_][a-zA-Z0-9_]*)(?!\])\b', code_only):
            var_name = m.group(1)
            if var_name == '_':
                continue
            issues[line_num].append(
                f"STYLE: Bare variable '${var_name}'. Use curly braces: '${{{var_name}}}'."
            )

        # Flag unsafe unbound checks in conditionals
        for m in re.finditer(r'(?:-z|-n)\s+"?\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}"?', code_only):
            var_name = m.group(1)
            issues[line_num].append(
                f"SAFETY: Unsafe unbound check for '${{{var_name}}}'. "
                f"Use '${{{var_name}-}}' inside -z/-n checks to prevent nounset crashes."
            )

        # Enforce spacing inside parentheses
        if re.search(r'=\+?\((?!\s|\)|$)', line):
            issues[line_num].append(
                "STYLE: Missing space after array initialization: use '=( ... )'."
            )

        if re.search(r'\$\((?!\s|\(|\)|$)', line):
            issues[line_num].append(
                "STYLE: Missing space after subshell start: use '$( ... )'."
            )

        missing_math_start = bool(re.search(r'\(\((?!\s|\))', struct_line))
        missing_math_end = bool(re.search(r'(?<!\s)(?<!\()\)\)', struct_line)) and '((' in struct_line

        if missing_math_start and missing_math_end:
            issues[line_num].append(
                "STYLE: Missing spaces inside math block: use '(( ... ))' or '$(( ... ))'."
            )
        elif missing_math_start:
            issues[line_num].append(
                "STYLE: Missing space after math start: use '(( ... ))' or '$(( ... ))'."
            )
        elif missing_math_end:
            issues[line_num].append(
                "STYLE: Missing space before math end: use '(( ... ))' or '$(( ... ))'."
            )

        for math_match in re.finditer(r'\(\((.+?)\)\)', struct_line):
            inner_math = math_match.group(1)

            # Flag variable expansions with '$' inside math context
            if re.search(r'\$([a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*.*?\})', inner_math):
                issues[line_num].append(
                    "STYLE: Variable expansion with '$' used inside math context. "
                    "Drop the '$' and quotes (e.g., use 'var' instead of '${var}')."
                )

        if re.search(r'(?<!\s)(?<!\()\)', struct_line_with_spacing) and (
             '$(' in line or '=(' in line or
             re.search(r'\)["\']?\s*(?:\)|$|;|\||&)', struct_line_with_spacing)
        ):

             # Ignore function definitions, case patterns, math, and AppleScript
            if not re.search(r'[a-zA-Z0-9_]+\(\)', struct_line) and \
               not re.search(r'^\s*\(?\s*[*a-zA-Z0-9_| \t"\'$\\-]+?\)', struct_line) and \
               '((' not in struct_line and '))' not in struct_line and \
               not re.search(r'\b(?:repeat|until|or|and)\b', struct_line) and \
               stripped != ')' and \
               not re.search(r'\b(?:length|substr|match|split|gsub|sub|index|int)\(', struct_line):
                issues[line_num].append(
                    "STYLE: Missing space before closing parenthesis: use '( ... )'."
                )

        raw_no_comment = line.split('#')[0] if '#' in line and not line.lstrip().startswith('#') else line

        # Process hybrid 'then' placement rule
        stripped_struct = struct_line.strip()
        if re.search(r'\b;?\s*then\b', struct_line):
            if stripped_struct == 'then':
                if line.strip() != 'then':
                    issues[line_num].append(
                        "STYLE: Isolated 'then' line contains trailing characters or comments. "
                        "Keep it pure."
                    )

                was_multiline = False

                for prev_idx in range(i, max(-1, i - 10), -1):
                    prev_line = orig_lines[prev_idx].strip()
                    if prev_idx < i and (is_line_continuation(prev_line) or any(s in prev_line for s in ('&&', '||'))):
                        was_multiline = True
                    if prev_line.startswith('if ') or prev_line.startswith('elif '):
                        if prev_idx < i:
                            was_multiline = True
                        break

                if not was_multiline:
                    issues[line_num].append(
                        "STYLE: Isolated 'then' on new line is only for multi-line conditionals. "
                        "Move to same line as 'if'."
                    )
            else:
                if re.search(r'(?:^|[({|&;]\s*|\b[a-zA-Z_]\w*=(?:["\']?\$\(\s*)?)(?:if|elif)\s+', stripped_struct):
                    pass
                elif re.search(r'\bthen\s*:\s*$', stripped_struct):
                    pass
                else:
                    issues[line_num].append(
                        "STYLE: Multi-line 'if' detected. "
                        "Move 'then' to its own dedicated line aligned with 'if'."
                    )

        elif re.search(r'(?:^|[({|&;]\s*|\b[a-zA-Z_]\w*=(?:["\']?\$\(\s*)?)(?:if|elif)\s+', stripped_struct):
            if not is_line_continuation(code_only.rstrip()) and not any(s in code_only for s in ('&&', '||')):
                if i + 1 < len(orig_lines) and orig_lines[i+1].strip() == 'then':
                    issues[line_num].append(
                        "STYLE: Simple 'if' detected. "
                        "Put '; then' on the same line for vertical density."
                    )

        # Flag unnecessary trailing semicolons
        if struct_line.rstrip().endswith(';') and not struct_line.rstrip().endswith(';;'):
            issues[line_num].append(
                "STYLE: Unnecessary trailing semicolon. "
                "In Bash, newlines act as command terminators."
            )

        # Check for trailing periods in terminal output
        if not is_comment and re.search(r'(?:\bprintf\b|\bmy_log\b|\bcustom_print\b|\becho\b)\s+.*?["\'][^"\']*?[^.]\.(\\n)?["\']', raw_no_comment):
            issues[line_num].append(
                "STYLE: Terminal output ends with a trailing period. "
                "Output strings should not end with punctuation (except ellipses '...')."
            )

        # Ban echo
        if not is_comment and re.search(r'\becho\b', raw_no_comment):
            issues[line_num].append(
                "STYLE: Use 'printf' instead of 'echo' for consistent cross-platform output."
            )

        # Ban POSIX test commands
        if not is_sh_script:

            # Enforce [[ ]] over [ ] for tests
            if re.search(r'(?:^|\||&&|;|do|then|if|elif|while|until)\s*\[\s+', struct_line):
                issues[line_num].append(
                    "STYLE: Use Bash keyword '[[ ... ]]' instead of POSIX '[ ... ]' test."
                )

            # Enforce == over = for string equality in Bash
            if re.search(r'\[\[(.*?[^\s!=<>+])\s+=\s+([^\s!=<>+].*?)\]\]', code_only):
                issues[line_num].append(
                    "STYLE: Use '==' instead of '=' for string comparison inside Bash '[[ ... ]]'."
                )

            # Suggest (( var++ )) instead of var=$(( var + 1 ))
            for inc_match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)=\$\(\(\s*(?:\$)?\1\s*([+-])\s*1\s*\)\)', code_only):
                var_name = inc_match.group(1)
                op = inc_match.group(2)
                issues[line_num].append(
                    f"NOTICE: Use Bash arithmetic evaluation '(( {var_name}{op}{op} ))' for cleaner increments."
                )

        # Enforce strict redirection formats
        if '&>' in struct_line:
            issues[line_num].append(
                "STYLE: Non-POSIX redirection '&>'. Use '> file 2>&1' instead."
            )
        if re.search(r'>&\s*(?!\d|-)[a-zA-Z/.]', struct_line):
            issues[line_num].append(
                "STYLE: Non-POSIX redirection '>&'. Use '> file 2>&1' instead."
            )

        if re.search(r'[^\s2]>\s*/dev/null', struct_line) or \
           re.search(r'>/dev/null', struct_line) or \
           re.search(r'>\s{2,}/dev/null', struct_line):
            issues[line_num].append(
                "STYLE: Inconsistent redirection spacing. "
                "Use ' > /dev/null ' instead of '>/dev/null'."
            )

        # Enforce embedded language safety
        if 'awk ' in raw_no_comment:
            if re.search(r'awk\s+"[^"]*\$', raw_no_comment):
                issues[line_num].append(
                    "WARNING: Unsafe awk quoting. Variables expand before awk sees them. "
                    "Use awk '...' and pass vars with -v."
                )

        # Check line-continuation backslash formatting
        if line.endswith(' ') and is_line_continuation(orig_lines[i].rstrip(' ')):
            issues[line_num].append(
                "STYLE: Trailing whitespace after line-continuation backslash '\\'. "
                "This breaks the pipeline."
            )

        # Check line wrapping after operators
        code_rstrip = code_only.rstrip()
        if is_line_continuation(code_rstrip):
            code_rstrip = code_rstrip[:-1].rstrip()

        if code_rstrip.endswith('&&') or code_rstrip.endswith('||') or (code_rstrip.endswith('|') and not code_rstrip.endswith('||')):

            # Ignore if inside case statement pattern
            issues[line_num].append(
                "STYLE: Line wrapped after operator. Operators (|, &&, ||) should be placed at the beginning of the next line."
            )

        indent = len(line) - len(stripped)

        # Catch Odd-Numbered Indentation
        if indent % 2 != 0:
            is_exempt = False
            if stripped.startswith('#') or stripped == "EOF":
                is_exempt = True
            elif re.match(r'^[\w.*|"-]+\)', stripped):
                is_exempt = True
            elif stripped.startswith('|') or stripped.startswith('&&') or stripped.startswith('||'):
                is_exempt = True
            elif indent == 1 and i > 0 and is_line_continuation(orig_lines[i-1]):
                is_exempt = True

            if not is_exempt:
                issues[line_num].append(f"STYLE: Odd-numbered indentation ({indent} spaces).")

        # Catch Missing Indentation After Block Starters (for strings/awk where shfmt is blind)
        if i > 0:
            prev_line = orig_lines[i-1]
            prev_stripped = prev_line.lstrip()
            prev_indent = len(prev_line) - len(prev_stripped)

            if re.search(r'(?:^|\s)(?:then|do|else|\{)\s*$', prev_stripped):
                expected_indent = prev_indent
                if prev_stripped.startswith('&&') or prev_stripped.startswith('||'):
                    expected_indent = prev_indent
                else:
                    expected_indent = prev_indent + 2

                if not stripped.startswith('#') and not is_empty:
                    if indent < expected_indent and stripped not in ('fi', 'done', '}', 'elif', 'else'):
                        issues[line_num].append("STYLE: Missing indentation after block start.")

                    if indent > expected_indent and stripped not in ('fi', 'done', '}', 'elif', 'else'):
                        issues[line_num].append(
                            f"STYLE: Inconsistent indentation jump (expected {expected_indent}, got {indent})."
                        )

        if stripped == '}' and indent != prev_indent - 2 and prev_stripped != '{':
            if prev_indent > 0:

                # Find matching brace via simple heuristic
                if indent > prev_indent - 2:
                    issues[line_num].append(
                        f"STYLE: Misaligned closing brace "
                        f"(expected {max(0, prev_indent-2)}, got {indent})."
                    )

        # Check cyclomatic complexity, POSIX syntax, and variable scoping
        if re.match(r'^\s*function\s+[a-zA-Z0-9_]+\s*\(\)', line):
            issues[line_num].append(
                "STYLE: Non-POSIX function declaration. Remove the 'function' keyword."
            )

        func_match = re.match(r'^\s*(?:function\s+)?([a-zA-Z0-9_]+)\s*\(\)', line)
        if func_match:
            in_function = True
            current_func_name = func_match.group(1)
            current_func_line = line_num
            func_complexity = 1
            current_func_exec_lines = 0
            local_vars_in_func = set()
            in_local_decl_block = False
            if line.rstrip().endswith('}'):
                in_function = False
        elif in_function:
            if line.rstrip() == '}':
                if current_func_name != 'main':
                    is_complex = func_complexity > 15
                    is_long = current_func_exec_lines > 50

                    if verbose:
                        if is_complex and is_long:
                            issues[current_func_line].append(
                                f"COMPLEXITY: Function '{current_func_name}' is too complex "
                                f"(Score: {func_complexity}, Max: 15) AND too long "
                                f"({current_func_exec_lines} lines). Consider breaking it down."
                            )
                        elif is_complex:
                            issues[current_func_line].append(
                                f"COMPLEXITY: Function '{current_func_name}' is too complex "
                                f"(Score: {func_complexity}, Max: 15). Consider breaking it down."
                            )
                        elif is_long:
                            issues[current_func_line].append(
                                f"COMPLEXITY: Function '{current_func_name}' is {current_func_exec_lines} "
                                "lines of code. Consider modularizing if possible."
                            )

                in_function = False
                local_vars_in_func.clear()
            else:
                if not is_comment and not is_empty:
                    current_func_exec_lines += 1

                clean_line = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', line)
                branches = len(re.findall(r'\b(if|elif|for|while|until)\b', clean_line))
                branches += len(re.findall(r'&&|\|\||;;', clean_line))
                func_complexity += branches

        # Lexicon checks for security and bad practices
        if not is_comment:
            if re.search(r'\b(?:curl|wget)\b.*?\|\s*(?:bash|sh)\b', raw_no_comment):
                issues[line_num].append(
                    "WARNING: Dangerous pattern detected (curl/wget piped to shell)."
                )
            if re.search(r'\beval\b', raw_no_comment):
                issues[line_num].append(
                    "WARNING: 'eval' command detected. "
                    "This is a severe security risk if input is unsanitized."
                )
            if re.search(r'\bchmod\s+777\b', raw_no_comment):
                issues[line_num].append(
                    "WARNING: 'chmod 777' detected. Use principle of least privilege."
                )
            safe_code_only = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', code_only)
            if re.search(r'\bif\b', safe_code_only):
                conditional_depth += 1
            if re.search(r'\bfi\b', safe_code_only):
                conditional_depth = max(0, conditional_depth - 1)

            if re.search(r'\bkill\s+-9\b', raw_no_comment):
                issues[line_num].append(
                    "WARNING: 'kill -9' detected. "
                    "Consider graceful termination (kill -TERM or -INT) first."
                )
            if re.search(r'\bset\s+(?:-[^\s]*x|-o\s+xtrace)\b', raw_no_comment):
                if conditional_depth == 0 and not any(s in raw_no_comment for s in ('&&', '||')):
                    issues[line_num].append(
                        "WARNING: 'set -x' (xtrace) detected. "
                        "Remove before committing to prevent secret leakage in CI/CD logs."
                    )

            # Portability and Bash 3.2 Compatibility Checks
            if re.search(r'\bdeclare\s+-[a-zA-Z]*[gA]', raw_no_comment):
                issues[line_num].append(
                    "WARNING: 'declare -g' or 'declare -A' detected. "
                    "Associative arrays and global declares require Bash 4.0+, breaking macOS (Bash 3.2) compatibility."
                )
            if re.search(r'\b(?:mapfile|readarray)\b', raw_no_comment):
                issues[line_num].append(
                    "WARNING: 'mapfile' or 'readarray' detected. "
                    "These require Bash 4.0+, breaking macOS (Bash 3.2) compatibility."
                )
            if re.search(r'\bsed\s+-i\b', raw_no_comment):
                issues[line_num].append(
                    "WARNING: 'sed -i' detected. In-place replacement syntax is fundamentally "
                    "incompatible between GNU and macOS/BSD. Use standard redirection."
                )

            # Highlight magic numbers
            magic_m = re.search(
                r'(?:sleep\s+|==\s*|!=\s*|-eq\s+|-ne\s+|-gt\s+|-lt\s+|-ge\s+|-le\s+|>\s*|<\s*)'
                r'(\d{2,})\b',
                raw_no_comment
            )
            if magic_m:
                num = int(magic_m.group(1))
                if num > 2 and num not in (255, 1492):
                    issues[line_num].append(
                        f"NOTICE: Magic number '{num}' detected in logic/sleep. "
                        "Consider extracting to a named constant."
                    )

        # Detect standalone 'local' declarations
        if in_function:
            if re.match(r'^\s*local\b', line):
                in_local_decl_block = True

            if in_local_decl_block:
                safe_line = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', line)
                if re.match(r'^\s*local\b', safe_line):
                    safe_line = safe_line.replace('local', '', 1)

                for var in safe_line.split():
                    if not var.startswith('-') and var != '\\':
                        local_vars_in_func.add(var.split('=')[0].strip())

                if not is_line_continuation(line.rstrip()):
                    in_local_decl_block = False

        # Detect variable assignments
        assigned_vars_on_line = []
        safe_code_for_assign = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', code_only).lstrip()
        if '"' in safe_code_for_assign or "'" in safe_code_for_assign:
            safe_code_for_assign = re.split(r'["\']', safe_code_for_assign, maxsplit=1)[0]

        prefix_match = re.match(r'^(local|export|readonly)\s+', safe_code_for_assign)

        if prefix_match:
            mod_prefix = prefix_match.group(1)
            remaining = safe_code_for_assign[prefix_match.end():]
            for token in remaining.split():
                if token.startswith('-'):
                    continue
                var_name = token.split('=', 1)[0].split('[')[0].split('+')[0]
                if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_name):
                    assigned_vars_on_line.append((var_name, mod_prefix))
        else:
            tokens = safe_code_for_assign.split()
            temp_vars = []
            is_pure_assignment = True
            for token in tokens:
                if token in ('\\', '(', ')'):
                    continue
                m = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)(?:\[.*\])?\+?=(?!=)', token)
                if m:
                    temp_vars.append((m.group(1), ""))
                else:
                    if temp_vars and any(t in tokens for t in ('&&', '||', ';')):
                        pass
                    else:
                        is_pure_assignment = False
                    break
            if is_pure_assignment:
                assigned_vars_on_line.extend(temp_vars)

        for math_match in re.findall(r'\(\((.+?)\)\)', struct_line):
            for v in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[-+*/%&|^<>!]?=|\+\+|--)', math_match):
                assigned_vars_on_line.append((v, ""))
            for v in re.findall(r'(?:\+\+|--)\s*([a-zA-Z_][a-zA-Z0-9_]*)\b', math_match):
                assigned_vars_on_line.append((v, ""))

        for read_match in re.findall(r'\bread\s+([^<>;|&]+)', safe_code_for_assign):
            tokens = [t for t in read_match.split() if not t.startswith('-') and t != 'read']
            for t in tokens:
                if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', t):
                    assigned_vars_on_line.append((t, ""))

        if not started_in_string and not quote_stack:
            for_match = re.search(r'\bfor\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', safe_code_for_assign)
            if for_match:
                assigned_vars_on_line.append((for_match.group(1), ""))

        for var_name, mod_prefix in assigned_vars_on_line:
            if in_function:
                if 'local' in mod_prefix or 'readonly' in mod_prefix:
                    if conditional_depth == 0:
                        local_vars_in_func.add(var_name)
                elif var_name not in local_vars_in_func and 'export' not in mod_prefix:
                    if var_name not in INTENTIONAL_GLOBALS and \
                       var_name not in STANDARD_ENV_VARS and \
                       not re.search(rf'(?<!\()\(\s*{var_name}=', line):

                        is_declared_later = False
                        in_declaration_statement = False
                        for future_idx in range(i + 1, len(orig_lines)):
                            future_line = orig_lines[future_idx].strip()
                            if future_line == '}':
                                break

                            if re.match(r'^\s*(readonly|local|export)\b', future_line):
                                in_declaration_statement = True

                            if in_declaration_statement:
                                if re.search(rf'\b{var_name}\b', future_line):
                                    is_declared_later = True
                                    break
                                if not is_line_continuation(future_line):
                                    in_declaration_statement = False

                        if not is_declared_later:
                            issues[line_num].append(
                                f"SCOPE: Variable '{var_name}' assigned in function "
                                "without 'local' or 'readonly'."
                            )

            # Check uppercase naming convention and readonly for constants
            if var_name.isupper() and not var_name.startswith('SC_'):
                if var_name not in STANDARD_ENV_VARS:
                    if verbose:
                        issues[line_num].append(
                            f"NOTICE: Variable '{var_name}' is UPPERCASE. "
                            "Is this really a user-configurable parameter?"
                        )
                    if 'readonly' not in mod_prefix and 'export' not in mod_prefix:
                        if var_name not in standalone_modifiers['readonly'] and var_name not in standalone_modifiers['export']:
                            issues[line_num].append(
                                f"NOTICE: Variable '{var_name}' is UPPERCASE but lacks 'readonly' modifier. "
                                "Consider adding 'readonly' if it is a constant, or use lowercase."
                            )

    def check_block_sorted(block, issues_dict):
        """
        Verify alphabetical sorting of contiguous variable assignments
        """
        names = [b[0].casefold() for b in block]
        is_dependent = False

        for idx, (_, _, content) in enumerate(block):
            if re.search(r'\$\{?\d+', content):
                is_dependent = True
                break
            for earlier_var, _, _ in block[:idx]:
                if re.search(rf'\$\{{?{re.escape(earlier_var)}\b', content):
                    is_dependent = True
                    break
            if is_dependent:
                break

        if not is_dependent and names != sorted(names):
            issues_dict[block[0][1]].append(
                f"STYLE: Variable assignment block is not alphabetically sorted "
                f"(starts with '{block[0][0]}')."
            )

    assign_block = []
    empty_lines_since_assign = 0

    for i, line in enumerate(orig_lines):
        line_num = i + 1
        stripped = line.strip()

        if not stripped:
            if assign_block:
                empty_lines_since_assign += 1
            continue

        if stripped.startswith('#'):
            if len(assign_block) > 1:
                check_block_sorted(assign_block, issues)
            assign_block = []
            empty_lines_since_assign = 0
            continue

        assign_match = re.match(
            r'^(?:local\s+|export\s+|readonly\s+)?([a-zA-Z_][a-zA-Z0-9_]*)(?:\[.*\])?\+?=', stripped
        )
        if assign_match:
            var_name = assign_match.group(1)
            if empty_lines_since_assign > 0 and assign_block:
                issues[line_num].append(
                    "STYLE: Empty line between variable assignment sets. "
                    "Consider grouping them or adding a comment."
                )
                if len(assign_block) > 1:
                    check_block_sorted(assign_block, issues)
                assign_block = []

            assign_block.append((var_name, line_num, stripped))
            empty_lines_since_assign = 0
        else:
            if len(assign_block) > 1:
                check_block_sorted(assign_block, issues)
            assign_block = []
            empty_lines_since_assign = 0

    if len(assign_block) > 1:
        check_block_sorted(assign_block, issues)

    # Check for consecutive printf combining
    prev_was_printf = False
    for ln, log_line in logical_lines:
        code_str = log_line
        in_sq = False
        in_dq = False
        for i, c in enumerate(log_line):
            if c == "'" and not in_dq:
                in_sq = not in_sq
            elif c == '"' and not in_sq:
                in_dq = not in_dq
            elif c == '#' and not in_sq and not in_dq:
                if i == 0 or log_line[i-1].isspace():
                    code_str = log_line[:i]
                    break
        code_str = code_str.strip()
        if not code_str:
            continue

        # Strip strings to safely check for operators like > without matching inside strings
        safe_code_str = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', code_str)
        has_array = bool(re.search(r'\$\{.+\[(?:@|\*)\]\}', code_str))
        has_redir = bool(re.search(r'[>|<]', safe_code_str))
        is_complex = has_array or has_redir

        if code_str.startswith('printf '):
            if prev_was_printf and not is_complex:
                issues[ln].append(
                    "NOTICE: Consecutive 'printf' commands detected. "
                    "Consider combining them into a single multi-line printf."
                )
            prev_was_printf = not is_complex
        else:
            prev_was_printf = False

    # Check for naked readonly and global assigned vars
    full_text = '\n'.join(orig_lines)
    all_assigned_vars = set(
        re.findall(
            r'(?:\b|^)(?:local\s+|export\s+|readonly\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\+?=',
            full_text
        )
    )
    safe_full_text = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', full_text)
    all_assigned_vars.update(
        re.findall(
            r'\bfor\s+([a-zA-Z_][a-zA-Z0-9_]*)\b',
            safe_full_text
        )
    )
    for math_match in re.findall(r'\(\((.+?)\)\)', full_text):
        for v in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[-+*/%&|^<>!]?=|\+\+|--)', math_match):
            all_assigned_vars.add(v)
        for v in re.findall(r'(?:\+\+|--)\s*([a-zA-Z_][a-zA-Z0-9_]*)\b', math_match):
            all_assigned_vars.add(v)
    for read_match in re.findall(r'\bread\s+([^<>;|&]+)', safe_full_text):
        tokens = [t for t in read_match.split() if not t.startswith('-') and t != 'read']
        for t in tokens:
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', t):
                all_assigned_vars.add(t)

    guarded_vars = set(
        re.findall(
            r'(?:-n|-z)\s+"?\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?:-|:-)?\}"?', full_text
        )
    )
    guarded_vars.update(re.findall(r'\$\{([a-zA-Z_][a-zA-Z0-9_]*):\?', full_text))

    for ln, log_line in logical_lines:
        list_match = re.match(r'^\s*(readonly|local|export)\s+(.*)', log_line)
        if list_match:
            modifier = list_match.group(1)
            args = list_match.group(2).strip()

            safe_args = re.sub(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', args)
            tokens = [t for t in safe_args.split() if not t.startswith('-')]

            if modifier == 'readonly':
                for t in tokens:
                    if '=' not in t:
                        var_name = t.rstrip(';')
                        if var_name in ('readonly', 'local', 'export'):
                            continue
                        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_name):
                            if var_name not in all_assigned_vars and var_name not in guarded_vars:
                                issues[ln].append(
                                    f"SAFETY: Naked readonly declaration leaves '{var_name}' unset. "
                                    "Explicitly assign '=\"\"' to prevent nounset crashes."
                                )

            var_names = [t.split('=')[0] for t in tokens]
            var_names = [v for v in var_names if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', v)]

            if len(var_names) > 1:
                names_lower = [v.casefold() for v in var_names]
                if names_lower != sorted(names_lower):
                    preview = ', '.join(var_names[:3])
                    if len(var_names) > 3:
                        preview += '...'
                    issues[ln].append(
                        f"STYLE: Variables in declaration list ({preview}) "
                        "are not alphabetically sorted."
                    )

    # Validate global strict mode
    if not (has_errexit and has_nounset and (has_pipefail or is_sh_script)):
        missing = []
        if not has_errexit:
            missing.append('errexit (-e)')
        if not has_nounset:
            missing.append('nounset (-u)')
        if not has_pipefail and not is_sh_script:
            missing.append('pipefail')
        issues[0] = issues.get(0, []) + [
            f"SAFETY: Missing strict mode declarations. Expected: {', '.join(missing)}."
        ]

    # Incorporate ShellCheck rules
    try:
        sc_args = ['shellcheck', '-f', 'gcc', '-a', '-S', 'style']

        # Mirror ShellCheck's native .shellcheckrc resolution behavior
        script_dir = os.path.dirname(os.path.abspath(filepath))
        has_rc = False

        # Check script directory and parents
        curr_dir = script_dir
        while True:
            if os.path.exists(os.path.join(curr_dir, '.shellcheckrc')) or os.path.exists(os.path.join(curr_dir, 'shellcheckrc')):
                has_rc = True
                break
            parent = os.path.dirname(curr_dir)
            if parent == curr_dir:
                break
            curr_dir = parent

        # Check current working directory (where linter is run from)
        if not has_rc and (os.path.exists('.shellcheckrc') or os.path.exists('shellcheckrc')):
            has_rc = True

        # Check home directory as final fallback (ShellCheck native behavior)
        if not has_rc and os.path.exists(os.path.expanduser('~/.shellcheckrc')):
            has_rc = True

        if not has_rc:
            sc_args.extend(['-o', 'all'])

        sc_args.append(filepath)

        kwargs = {'capture_output': True, 'text': True}
        if filepath == '-':
            kwargs['input'] = stdin_content.decode('utf-8')

        sc_result = subprocess.run(sc_args, **kwargs)
        for sc_line in sc_result.stdout.splitlines():
            m = re.match(r'^[^:]+:(\d+):\d+: ([^:]+): (.*)$', sc_line)
            if m:
                ln = int(m.group(1))
                msg = m.group(3)
                sev = m.group(2).upper()

                # Suppress SC2250 (Bare variables) because our custom styling handles it better
                if '[SC2250]' in msg:
                    continue

                if ln not in issues:
                    issues[ln] = []

                # Suppress duplicate identical SC rules on same line
                sc_code_match = re.search(r'\[(SC\d+)\]', msg)
                if sc_code_match:
                    sc_code = sc_code_match.group(1)
                    if any(f"[{sc_code}]" in existing for existing in issues[ln]):
                        continue

                issues[ln].append(f"SHELLCHECK {sev}: {msg}")
    except FileNotFoundError:
        print("CRITICAL ERROR: 'shellcheck' binary not found. Please install ShellCheck to run this linter.", file=sys.stderr)
        sys.exit(1)

    # Enforce structural checks via shfmt
    try:
        sf_args = ['shfmt', '-d', '-i', '2', filepath]
        kwargs = {'capture_output': True, 'text': True}
        if filepath == '-':
            kwargs['input'] = stdin_content.decode('utf-8')

        sf_result = subprocess.run(sf_args, **kwargs)
        diff_lines = sf_result.stdout.splitlines()

        current_line = 0
        old_buffer, new_buffer = [], []

        def flush_buffers():
            """
            Synchronize buffers and flush shfmt formatting results
            """
            def clean_for_match(s):
                """
                Clean bash syntax structure to match diff accurately
                """
                s = s.strip()
                s = re.sub(r'^(?:&&|\|\||\||\bthen\b)\s*', '', s)
                s = re.sub(r'\s*(?:\\|;|then|; then|&&|\|\||\|)$', '', s)
                return re.sub(r'\s+', '', s)

            new_buffer_consumed = [False] * len(new_buffer)

            for old_text, ln in old_buffer:
                old_stripped = old_text.strip()
                if not old_stripped or old_stripped.startswith('#'):
                    continue

                old_clean = clean_for_match(old_text)
                if not old_clean:
                    continue

                matched_idx = -1
                for idx, n in enumerate(new_buffer):
                    if not new_buffer_consumed[idx] and clean_for_match(n) == old_clean:
                        matched_idx = idx
                        break

                if matched_idx != -1:
                    new_buffer_consumed[matched_idx] = True
                    new_text = new_buffer[matched_idx]
                    old_indent = len(old_text) - len(old_text.lstrip())
                    new_indent = len(new_text) - len(new_text.lstrip())

                    if old_indent != new_indent:
                        in_case = False
                        for prev_idx in range(ln - 1, max(-1, ln - 100), -1):
                            prev_line = orig_lines[prev_idx].strip()
                            if prev_line.startswith('case '):
                                in_case = True
                                break
                            elif prev_line == 'esac':
                                break

                        if in_case and old_indent == new_indent + 2:
                            continue

                        if ln not in issues:
                            issues[ln] = []
                        issues[ln].append(
                            f"SHFMT: Structural mismatch (expected {new_indent} spaces, "
                            f"got {old_indent})"
                        )

            old_buffer.clear()
            new_buffer.clear()

        for line in diff_lines:
            if line.startswith('---') or line.startswith('+++'):
                continue
            if line.startswith('@@'):
                flush_buffers()
                m = re.search(r'-(\d+)', line)
                if m:
                    current_line = int(m.group(1)) - 1
                continue
            if line.startswith(' '):
                flush_buffers()
                current_line += 1
            elif line.startswith('-'):
                old_buffer.append((line[1:], current_line + 1))
                current_line += 1
            elif line.startswith('+'):
                new_buffer.append(line[1:])
        flush_buffers()
    except FileNotFoundError:
        print("CRITICAL ERROR: 'shfmt' binary not found. Please install shfmt to run this linter.", file=sys.stderr)
        sys.exit(1)

    # Deduplicate redundant warnings
    for ln, msgs in issues.items():

        # Deduplicate SHFMT indentation
        has_style_indent = any(re.match(r'^STYLE: (Inconsistent indentation jump|Missing indentation after block start|Odd-numbered indentation|Misaligned closing brace)', m) for m in msgs)
        if has_style_indent:
            msgs = [m for m in msgs if not m.startswith("SHFMT: Structural mismatch")]

        # Deduplicate ShellCheck SC2292 (Prefer [[ ]])
        has_style_bracket = any("Use Bash keyword '[[ ... ]]'" in m for m in msgs)
        if has_style_bracket:
            msgs = [m for m in msgs if "[SC2292]" not in m]

        issues[ln] = msgs

    return issues


################################################################################
# Main Execution Entry Point
################################################################################

if __name__ == '__main__':
    USAGE_MSG = "Usage: shellens [--markdown] [--verbose] [--sh] [--no-color] <path_to_script1.sh> [path_to_script2.sh ...]"
    args = sys.argv[1:]

    if not args or '--help' in args or '-h' in args:
        print(USAGE_MSG)
        sys.exit(0 if args else 1)

    if '--version' in args or '-v' in args:
        print(f"Shellens v{__version__}")
        sys.exit(0)

    use_markdown = False
    use_verbose = False
    force_sh = False
    use_no_color = not sys.stdout.isatty() or os.environ.get('NO_COLOR')
    target_scripts = []

    args_iter = iter(args)
    for arg in args_iter:
        if arg == '--':
            target_scripts.extend(list(args_iter))
            break
        elif arg == '--markdown':
            use_markdown = True
        elif arg == '--verbose':
            use_verbose = True
        elif arg == '--sh':
            force_sh = True
        elif arg == '--no-color':
            use_no_color = True
        elif arg.startswith('-') and arg != '-':
            print(f"Error: Unknown option '{arg}'")
            print(USAGE_MSG)
            sys.exit(1)
        else:
            matches = glob.glob(arg, recursive=True)
            if matches and arg != '-':
                target_scripts.extend(matches)
            else:
                target_scripts.append(arg)

    if use_no_color or use_markdown:
        C_RESET = C_BOLD = C_RED = C_YELLOW = C_CYAN = C_BLUE = C_DIM = ''

    if not target_scripts:
        print("Error: No script paths provided")
        sys.exit(1)

    has_missing_files = False
    for script in target_scripts:
        if script == '-':
            continue
        if not os.path.exists(script):
            print(f"Error: File {script} not found")
            has_missing_files = True
        elif not os.path.isfile(script):
            print(f"Error: Path {script} is not a regular file")
            has_missing_files = True
        elif not os.access(script, os.R_OK):
            print(f"Error: File {script} is not readable (Permission Denied)")
            has_missing_files = True

    if has_missing_files:
        sys.exit(1)

    stdin_content = None
    if '-' in target_scripts:
        stdin_content = sys.stdin.read().encode('utf-8')

    all_issues = {}
    for script in target_scripts:
        result = check_format(script, verbose=use_verbose, force_sh=force_sh, stdin_content=stdin_content)
        if result is not None:
            all_issues[script] = result
        else:
            sys.exit(1)

    dead_code_issues = analyze_dead_code(target_scripts, stdin_content=stdin_content)

    total_project_issues = 0

    for script in target_scripts:
        issues = all_issues.get(script, {})
        dead_issues = dead_code_issues.get(script, {})

        for ln, msgs in dead_issues.items():
            if ln not in issues:
                issues[ln] = []
            issues[ln].extend(msgs)

        script_total = sum(len(msgs) for msgs in issues.values())
        total_project_issues += script_total

        if script_total == 0:
            print(f"Perfect! No formatting, style, or dead code issues found in {script}")
            continue

        script_display_name = "<stdin>" if script == '-' else script
        script_name_base = "stdin" if script == '-' else os.path.basename(script).replace('.', '-')

        if use_markdown:
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

                        # Escape pipes, newlines, and markdown special chars to prevent weird formatting (e.g. math rendering)
                        safe_desc = desc.replace('|', '&#124;').replace('\n', ' ')
                        safe_desc = safe_desc.replace('$', '&#36;').replace('_', '&#95;')
                        safe_desc = safe_desc.replace('*', '&#42;')

                        # Add ShellCheck Wiki Link
                        if 'SHELLCHECK' in cat:
                            sc_match = re.search(r'\[(SC\d+)\]', safe_desc)
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

    if (total_project_issues > 0 or has_missing_files) and not use_markdown:
        sys.exit(1)
