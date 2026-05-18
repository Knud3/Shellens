#!/usr/bin/env python3

"""
Unit tests for Shellens
"""

import os
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shellens import check_format, clear_ast_cache, __version__, get_color, C_RED, C_YELLOW, C_CYAN, C_BLUE, C_RESET, analyze_dead_code


class TestShellens(unittest.TestCase):
    """Test suite for Shellens formatting and static analysis rules"""
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.orig_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.test_script = os.path.join(self.temp_dir.name, 'test_dummy.sh')

    def tearDown(self):
        """Clean up test environment"""
        os.chdir(self.orig_cwd)
        self.temp_dir.cleanup()
        clear_ast_cache()

    def write_script(self, code):
        """Write code to temporary script"""
        with open(self.test_script, 'w', encoding='utf-8') as f:
            f.write(code)

    def get_issues(self, strict=True):
        """Retrieve issues from temporary script"""
        issues = check_format(self.test_script, strict=strict, info=True)
        flat = []
        if issues:
            for ln, msgs in issues.items():
                if len(msgs) != len(set(msgs)):
                    raise AssertionError(f"Duplicate issues found on line {ln}: {msgs}")
                for m in msgs:
                    flat.append((ln, m))
        return flat

    def assertIssue(self, issues, line_num, substring):
        """Assert issue is present on specific line"""
        matching_issues = [msg for ln, msg in issues if ln == line_num and substring in msg]
        self.assertEqual(len(matching_issues), 1, f"Expected exactly 1 issue '{substring}' on line {line_num}. Got {len(matching_issues)}. All issues on line: {[m for ln, m in issues if ln == line_num]}")

    def assertNoIssue(self, issues, line_num, substring):
        """Assert issue is not present on specific line"""
        found = any(ln == line_num and substring in msg for ln, msg in issues)
        self.assertFalse(found, f"Did not expect issue '{substring}' on line {line_num}. Got: {[m for ln, m in issues if ln == line_num]}")

    def test_missing_space_parenthesis(self):
        """Flag missing space before closing parenthesis"""
        self.write_script(
            "#!/bin/bash\n"
            "my_array=( 1 2 3)\n"                                   # Line 2: Fails (missing space)
            "my_array=( 1 2 3 )\n"                                  # Line 3: Passes
            "awk 'length(str)'\n"                                   # Line 4: Passes (inside awk string)
            "case $x in *) ;;\n"                                    # Line 5: Passes (case statement)
            "(( x + 1 ))\n"                                         # Line 6: Passes (math block)
            "echo \")\"\n"                                          # Line 7: Passes (inside string)
            "my_array=(\n"
            "  1 2 3\n"
            ")\n"                                                   # Line 10: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 3, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 4, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 5, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 6, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 7, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 10, "Missing space before closing parenthesis")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 2, "Missing space before closing parenthesis")

    def test_if_statement(self):
        """Enforce multi-line vs single-line 'if' structure and 'then' isolation"""
        self.write_script(
            "#!/bin/bash\n"
            "if [[ $a == 1 ]] \\\n"
            "  && [[ $b == 2 ]]; then\n"                            # Line 3: Fails (then on same line as condition end)
            "  echo 1\n"
            "fi\n"
            "if [[ $a == 1 ]] \\\n"
            "  && [[ $b == 2 ]]\n"
            "then\n"                                                # Line 8: Passes (then on its own line)
            "  echo 2\n"
            "fi\n"
            "if [[ $a == 1 ]]; then\n"                              # Line 11: Passes (single line condition)
            "  echo 3\n"
            "fi\n"
            "\n"
            "if [[ 1 == 1 ]]\n"                                     # Line 15: Fails (simple if)
            "then\n"
            "  echo 1\n"
            "fi\n"                                                  # Line 18: Passes
            "\n"
            "if [[ 2 == 2 ]] \\\n"
            "  && [[ 3 == 3 ]]\n"
            "then # Some comment\n"                                 # Line 22: Fails (isolated 'then' has trailing comment)
            "  echo 3\n"
            "fi\n"
            "\n"
            "if ( \n"
            "  true \n"
            "); then :\n"                                           # Line 28: Passes (then : is allowed exception for multi-line)
            "fi\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Multi-line 'if' detected")
        self.assertNoIssue(issues, 8, "Multi-line 'if' detected")
        self.assertNoIssue(issues, 11, "Multi-line 'if' detected")
        self.assertIssue(issues, 15, "Simple 'if' detected")
        self.assertNoIssue(issues, 18, "Simple 'if' detected")
        self.assertIssue(issues, 22, "Isolated 'then' line contains trailing characters or comments")
        self.assertNoIssue(issues, 28, "Multi-line 'if' detected")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 3, "Multi-line 'if' detected")
        self.assertNoIssue(issues_non_strict, 15, "Simple 'if' detected")
        self.assertNoIssue(issues_non_strict, 22, "Isolated 'then' line contains trailing characters or comments")

    def test_unsafe_unbound(self):
        """Flag unsafe unbound variable checks"""
        self.write_script(
            "#!/bin/bash\n"
            "if [[ -z \"${var}\" ]]; then echo 1; fi\n"             # Line 2: Fails (unsafe unbound check)
            "if [[ -z \"${var-}\" ]]; then echo 2; fi\n"            # Line 3: Passes (safe check)
            "if [[ -n \"${var:-}\" ]]; then echo 3; fi\n"           # Line 4: Passes (safe check)
            "if [[ $var == 1 ]]; then echo 4; fi\n"                 # Line 5: Passes (not -z/-n)
            "if [ -z \"$1\" ]; then echo 6; fi\n"                   # Line 6: Fails (only in strict mode)
            "if [ -n \"${POSIXLY_CORRECT+1}\" ]; then echo 7; fi\n" # Line 7: Passes (alternate value expansion)
            "if [[ -z \"${sources[*]}\" ]]; then echo 8; fi\n"      # Line 8: Fails (naked array check)
            "if [[ -z \"${sources[@]-}\" ]]; then echo 9; fi\n"     # Line 9: Passes (safe array check)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Unsafe unbound check")
        self.assertNoIssue(issues, 3, "Unsafe unbound check")
        self.assertNoIssue(issues, 4, "Unsafe unbound check")
        self.assertNoIssue(issues, 5, "Unsafe unbound check")
        self.assertIssue(issues, 6, "Unsafe unbound check")
        self.assertNoIssue(issues, 7, "Unsafe unbound check")
        self.assertIssue(issues, 8, "Unsafe unbound check")
        self.assertNoIssue(issues, 9, "Unsafe unbound check")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 6, "Unsafe unbound check")

    def test_alphabetical_sort(self):
        """Enforce alphabetical sorting"""
        self.write_script(
            "#!/bin/bash\n"
            "b_var=1\n"                                             # Line 2: Fails (unsorted)
            "a_var=2\n"
            "\n"
            "c_var=3\n"                                             # Line 5: Passes
            "d_var=4\n"
            "\n"
            "echo foo\n"
            "\n"
            "local b a\n"                                           # Line 10: Fails (unsorted variables)
            "local c d\n"                                           # Line 11: Passes (sorted variables)
            "\n"
            "echo foo\n"
            "\n"
            "readonly color_black=''; readonly color_blue=''; readonly color_cyan=''\n"
            "readonly c=1; readonly a=2\n"                          # Line 16: Fails (not alphabetically sorted)
            "\n"
            "echo foo\n"
            "\n"
            "readonly b=1\n"                                        # Line 20: Fails (block is not alphabetically sorted)
            "readonly a=2\n"
            "\n"
            "echo foo\n"
            "\n"
            "b=1 # Variable b\n"                                    # Line 25: Fails (inline comments do not exempt sorting)
            "a=2 # Variable a\n"
            "\n"
            "echo foo\n"
            "\n"
            "readonly color_cyan=''; readonly color_blue=''\n"      # Line 30: Fails (not alphabetically sorted)
            "\n"
            "echo foo\n"
            "\n"
            "random_id=\"$( LC_ALL=C date )\"\n"                    # Line 34: Passes (not declaration list)
            "\n"
            "echo foo\n"
            "\n"
            "orig_cwd=\"${PWD}\"\n"
            "fmt_reset=\"$( tput sgr0 2> /dev/null || true )\"\n"
            "tty_dev=\"$( tty )\"\n"
            "TZ=\"UTC\"\n"                                          # Line 41: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "alphabetically sorted")
        self.assertNoIssue(issues, 5, "alphabetically sorted")
        self.assertIssue(issues, 10, "Variables in declaration list")
        self.assertNoIssue(issues, 11, "Variables in declaration list")
        self.assertIssue(issues, 16, "alphabetically sorted")
        self.assertIssue(issues, 20, "alphabetically sorted")
        self.assertIssue(issues, 25, "alphabetically sorted")
        self.assertIssue(issues, 30, "alphabetically sorted")
        self.assertNoIssue(issues, 34, "alphabetically sorted")
        self.assertNoIssue(issues, 41, "alphabetically sorted")

    def test_consecutive_printf(self):
        """Flag consecutive printf statements"""
        self.write_script(
            "#!/bin/bash\n"
            "printf \"a\"\n"
            "printf \"b\"\n"                                        # Line 3: Fails (consecutive)
            "printf \"c\"\n"
            "echo \"d\"\n"
            "printf \"e\"\n"                                        # Line 6: Passes
            "printf \"%s\" \"${arr[@]}\"\n"
            "printf \"f\"\n"                                        # Line 8: Passes (due to array mapping above)
            "printf \"g\" >/dev/null\n"
            "printf \"h\"\n"                                        # Line 10: Passes (due to redirection above)
            "printf \"i %d\" \"${#arr[@]}\"\n"
            "printf \"j\"\n"                                        # Line 12: Passes (due to array mapping above)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Consecutive 'printf'")
        self.assertNoIssue(issues, 6, "Consecutive 'printf'")
        self.assertNoIssue(issues, 8, "Consecutive 'printf'")
        self.assertNoIssue(issues, 10, "Consecutive 'printf'")
        self.assertNoIssue(issues, 12, "Consecutive 'printf'")

    def test_scope(self):
        """Enforce local scope for variables assigned in functions"""
        self.write_script(
            "#!/bin/bash\n"
            "global_var=1\n"
            "func_a() {\n"
            "  local_var=2\n"                                       # Line 4: Fails (missing local)
            "  local local_ok=3\n"                                  # Line 5: Passes
            "  global_var=4\n"                                      # Line 6: Fails (shadowing global)
            "  verbosity=5\n"                                       # Line 7: Passes (INTENTIONAL_GLOBALS)
            "  (( math_var=6 ))\n"                                  # Line 8: Fails (assigned in math block)
            "  (( math_var2++ ))\n"                                 # Line 9: Fails (assigned in math block)
            "  read -r read_var < file\n"                           # Line 10: Fails (assigned via read)
            "  for loop_var in 1 2 3; do echo 1; done\n"            # Line 11: Fails (assigned via for loop)
            "  local ok_math ok_read ok_loop\n"
            "  (( ok_math = 1 ))\n"                                 # Line 13: Passes (declared local above)
            "  read -r ok_read < file\n"                            # Line 14: Passes (declared local above)
            "  for ok_loop in 1; do echo 1; done\n"                 # Line 15: Passes (declared local above)
            "  USER=\"admin\"\n"                                    # Line 16: Passes (STANDARD_ENV_VARS exempted)
            "  echo \"$(subshell_var=1; echo $subshell_var)\"\n"    # Line 17: Passes (assigned in subshell)
            "  ( subshell_var2=2; echo 1 )\n"                       # Line 18: Passes (assigned in subshell)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "SCOPE")
        self.assertNoIssue(issues, 5, "SCOPE")
        self.assertIssue(issues, 6, "SCOPE")
        self.assertNoIssue(issues, 7, "SCOPE")
        self.assertIssue(issues, 8, "SCOPE")
        self.assertIssue(issues, 9, "SCOPE")
        self.assertIssue(issues, 10, "SCOPE")
        self.assertIssue(issues, 11, "SCOPE")
        self.assertNoIssue(issues, 13, "SCOPE")
        self.assertNoIssue(issues, 14, "SCOPE")
        self.assertNoIssue(issues, 15, "SCOPE")
        self.assertNoIssue(issues, 16, "SCOPE")
        self.assertNoIssue(issues, 17, "SCOPE")
        self.assertNoIssue(issues, 18, "SCOPE")

        # Verify escaped backslashes do not break local scope tracking
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  local a=1\\\\\n"
            "  b=2\n"                                               # Line 4: Fails (flagged as scope issue)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "SCOPE: Variable 'b' assigned in function without 'local' or 'readonly'.")

        # Enforce local scope for array assignments in functions
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  arr[0]=1\n"                                          # Line 3: Fails (assigned without local)
            "  arr+=(\"a\")\n"                                      # Line 4: Fails (assigned without local)
            "  my_array=( \"--arg=1\" \"--arg=2\" )\n"              # Line 5: Fails (initialization without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'arr' assigned in function")
        self.assertIssue(issues, 4, "SCOPE: Variable 'arr' assigned in function")
        self.assertIssue(issues, 5, "SCOPE: Variable 'my_array' assigned in function")

        # Verify nested math scopes are tracked correctly
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  (( math_var = $(( math_inner + 1 )) ))\n"            # Line 3: Fails (math_var assigned)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'math_var' assigned in function")
        self.assertNoIssue(issues, 3, "SCOPE: Variable 'math_inner' assigned in function")

        # Enforce scope checks on variables assigned via command substitution
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  message=\"$( printf '%b\\n' \"${2}\" | sed 's/^[[:space:]]*//' )\"\n" # Line 3: Fails (assigned without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'message' assigned in function")

        # Enforce scope checks on variables assigned across multiple lines with trailing backslash
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  logline=\"$( printf '%s\\n' \"${2}\" \\\n"           # Line 3: Fails (assigned without local)
            "    | sed -e ':a' -e 'N;$!ba' )\"\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'logline' assigned in function")

        # Read command variable scope inside while loop condition
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  while IFS='' read -r line; do\n"                     # Line 3: Fails (variable assigned without local)
            "    echo 1\n"
            "  done\n"
            "}\n"
            "func_b() {\n"
            "  while read -r line_alt; do\n"                        # Line 8: Fails (variable assigned without local)
            "    echo 1\n"
            "  done\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'line' assigned in function")
        self.assertIssue(issues, 8, "SCOPE: Variable 'line_alt' assigned in function without 'local' or 'readonly'.")

        # If array is declared via local -a, subsequent assignments without local are fine
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  local -a arr\n"
            "  arr=()\n"                                            # Line 4: Passes
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'arr' assigned in function")

    def test_line_length_and_heredoc(self):
        """Enforce maximum line length limit, honoring strings and heredoc boundaries"""
        long_code = "if [[ $a == 1 && $b == 2 && $c == 3 && $d == 4 && $e == 5 && $f == 6 && $g == 7 ]]; then"
        long_string = "a=" + "1" * 79
        exact_combined = "      combined=\"$( printf \\\"%s\\n\\\" \\\"${desc_am}\\\" | awk 'NF {printf \\\"%s | \\\", $0}' | sed 's/ | $//' )\""
        printf_multiline = (
            "    printf \"========================================================================================================\\n\\\n"
            "========================================================================================================\\n\"\n"
        )
        self.write_script(
            f"#!/bin/bash\n"
            f"{long_code}\n"                                        # Line 2: Fails (code line > 80)
            f"{long_string}\n"                                      # Line 3: Passes (uninterrupted string exempted)
            f"{exact_combined}\n"                                   # Line 4: Fails (code line > 80 with spaces)
            f"{printf_multiline}"                                   # Line 5: Passes (printf multiline is exempted)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Code line exceeds 80")
        self.assertNoIssue(issues, 3, "Code line exceeds 80")
        self.assertIssue(issues, 4, "Code line exceeds 80")
        self.assertNoIssue(issues, 5, "Code line exceeds 80")
        self.assertNoIssue(issues, 6, "Code line exceeds 80")

        # Verify heredoc termination marker detection and line length exemptions
        self.write_script(
            "#!/bin/bash\n"
            "cat << EOF\n"
            "  EOF\n"
            "  this is still inside heredoc but will exceed 80 chars if not treated as heredoc! this line is very very very long and exceeds 80 characters.\n" # Line 4: Passes
            "EOF\n"
            "cat <<- EOF_DASH\n"
            "\tEOF_DASH\n"
            "  this is outside heredoc but will exceed 80 chars because heredoc closed! this line is very very very long and exceeds 80 characters.\n" # Line 8: Fails (outside heredoc)
            "cat << EOF_TRAIL\n"
            "EOF_TRAIL; echo 1\n"                                   # Line 10: Fails (trailing chars on marker)
            "EOF_TRAIL\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "Code line exceeds 80 characters")
        self.assertIssue(issues, 8, "Code line exceeds 80 characters")
        self.assertIssue(issues, 10, "Heredoc termination marker")

        # Verify open and quoted heredocs pass line length
        self.write_script(
            "#!/bin/bash\n"
            "cat << 'EOF'\n"
            "  This is a very very long line inside a heredoc that exceeds 80 characters by a lot!\n" # Line 3: Passes (inside heredoc)
            "EOF\n"
            "cat <<EOF\n"
            "this line is incredibly long and definitely exceeds the eighty character limit that is set for code\n" # Line 6: Passes
            "set matching_items to windows whose title contains item_title and another condition that exceeds length\n" # Line 7: Passes
            "EOF\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "Code line exceeds 80")
        self.assertNoIssue(issues, 6, "Code line exceeds 80")
        self.assertNoIssue(issues, 7, "Code line exceeds 80")

    def test_math_dollar(self):
        """Flag variable expansion with dollar sign in math context"""
        self.write_script(
            "#!/bin/bash\n"
            "(( ${var} + 1 ))\n"                                    # Line 2: Fails ($ inside math context)
            "(( var + 1 ))\n"                                       # Line 3: Passes
            "echo \"(( ${var} ))\"\n"                               # Line 4: Passes (inside string)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Variable expansion with '$' used inside math context")
        self.assertNoIssue(issues, 3, "Variable expansion with '$' used inside math context")
        self.assertNoIssue(issues, 4, "Variable expansion with '$' used inside math context")

    def test_operator_wrapping(self):
        """Flag lines wrapped after operators"""
        self.write_script(
            "#!/bin/bash\n"
            "echo a | \\\n"                                         # Line 2: Fails (wrapped after operator)
            "  echo b\n"
            "echo c \\\n"                                           # Line 4: Passes
            "  | echo d\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Line wrapped after operator")
        self.assertNoIssue(issues, 4, "Line wrapped after operator")

    def test_comments(self):
        """Enforce comment formatting rules"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
            "# The bad comment.\n"                                  # Line 3: Fails (trailing period, article, no padding)
            "\n"
            "# Good comment\n"                                      # Line 5: Passes
            "\n"
            "printf foo\n"
            "\n"
            "echo 1\n"
            "\n"
            "# Bad comment.\n"                                      # Line 11: Fails (trailing period)
            "\n"
            "#######\n"                                             # Line 13: Fails (header length)
            "echo 2\n"
            "#####\n"                                               # Line 15: Fails (1 or 2 empty lines)
            "echo 3\n"
            "\n"
            "# Loading something...\n"                              # Line 18: Fails (ellipsis in comment)
            "echo 4 # inline comment\n"
            "# Following comment\n"                                 # Line 20: Fails (indentation doesn't match inline comment)
            "\n"
            "printf foo\n"
            "\n"
            "echo 5 # inline comment\n"
            "       # comment continues\n"                          # Line 25: Passes (aligned with previous inline comment)
            "\n"
            "printf foo\n"
            "\n"
            "# var=1\n"                                             # Line 29: Passes (commented code)
            "# echo 5\n"                                            # Line 30: Passes (commented code)
            "\n"
            "printf foo\n"
            "\n"
            "echo 1\n"
            "\n"
            "# This is line one\n"
            "# This is line two\n"                                  # Line 37: Fails (multi-line comment not in header block)
            "echo 2\n"
            "\n"
            "################################################################################\n"
            "# This is line one in header\n"                        # Line 41: Passes
            "# This is line two in header\n"                        # Line 42: Passes
            "#   This line is fine\n"                               # Line 43: Passes
            "Not good\n"                                            # Line 44: Fails (missing '# ')
            " Not good\n"                                           # Line 45: Fails (missing '# ')
            "  Not good\n"                                          # Line 46: Fails (missing '# ')
            "#Not good\n"                                           # Line 47: Fails (missing space after '#')
            "################################################################################\n"
            "# Not good\n"                                          # Line 49: Fails (not exactly 1 empty line before comment)
            "\n"
            "printf foo\n"
            "\n"
            "echo 1\n"
            "\n"
            "\n"
            "echo 2\n"                                              # Line 56: Fails (2 empty lines before it)
            "\n"
            "################################################################################\n" # Line 58: Passes (1 empty line)
            "# Header\n"
            "################################################################################\n"
            "\n"
            "\n"
            "################################################################################\n" # Line 63: Passes (2 empty lines allowed before header)
            "# Header 2\n"
            "################################################################################\n" # Line 65: Passes
            "\n"
            "\n"
            "\n"
            "################################################################################\n"
            "# Header 3\n"
            "################################################################################\n"
            "\n"
            "printf foo\n"
            "\n"
            "#######################################\n"             # Line 75: Fails (header block too short)
            "# Bad Header\n"
            "#######################################\n"             # Line 77: Fails (header block too short)
            "################################################################################\n" # Line 78: Passes (exact 80 chars)
            "# Good Header\n"
            "################################################################################\n" # Line 80: Passes (exact 80 chars)
            "\n"
            "printf foo\n"
            "\n"
            "################################################################################\n" # Line 84: Passes (Header at start/after shebang doesn't need empty lines, although there is echo foo)
            "# Header\n"
            "################################################################################\n"
            "\n"
            "printf foo\n"
            "\n"
            "PROG_NAME=\"A\"  # Inline comment\n"                   # Line 90: Passes (inline comments don't count as blocks)
            "\n"
            "printf foo\n"
            "\n"
            "echo 1\n"
            "# Read the file\n"                                     # Line 95: Fails (contains 'the')
            "echo 2\n"
            "\n"
            "################################################################################\n"
            "# Another Header\n"
            "################################################################################\n"
            "\n"
            "# Normal comment directly after header with one line space\n" # Line 102: Passes
            "echo 3\n"
            "echo \"# string\" | grep \"#\"\n"
            "  # Comment indented normally\n"                       # Line 105: Passes (hash in previous line is inside string)
            "  echo 4\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 105, "Comment indentation mismatch")
        self.assertNoIssue(issues, 102, "Comment must be preceded by exactly one empty line")
        self.assertNoIssue(issues, 102, "No code between this comment and previous comment block")
        self.assertIssue(issues, 3, "Comment must be preceded by exactly one empty line")
        self.assertIssue(issues, 3, "articles")
        self.assertNoIssue(issues, 5, "Comment must be preceded by exactly one empty line")
        self.assertNoIssue(issues, 5, "articles")
        self.assertIssue(issues, 11, "Comment ends with trailing period")
        self.assertIssue(issues, 13, "Header block must be exactly 80 '#' characters")
        self.assertIssue(issues, 15, "Header block must be preceded by 1 or 2 empty lines")
        self.assertIssue(issues, 18, "Comment ends with trailing period")
        self.assertIssue(issues, 20, "Comment indentation mismatch")
        self.assertNoIssue(issues, 25, "Comment indentation mismatch")
        self.assertNoIssue(issues, 29, "No code between this comment")
        self.assertNoIssue(issues, 30, "No code between this comment")
        self.assertIssue(issues, 37, "Consecutive comment lines detected")
        self.assertNoIssue(issues, 41, "Consecutive comment lines detected")
        self.assertNoIssue(issues, 42, "Consecutive comment lines detected")
        self.assertNoIssue(issues, 43, "Consecutive comment lines detected")
        self.assertNoIssue(issues, 65, "Consecutive comment lines detected")
        self.assertIssue(issues, 44, "Lines inside header block must begin with '# '")
        self.assertIssue(issues, 45, "Lines inside header block must begin with '# '")
        self.assertIssue(issues, 46, "Lines inside header block must begin with '# '")
        self.assertIssue(issues, 47, "Lines inside header block must begin with '# '")
        self.assertIssue(issues, 49, "Comment must be preceded by exactly one empty line")
        self.assertIssue(issues, 56, "Too many empty lines")
        self.assertNoIssue(issues, 58, "Too many empty lines")
        self.assertNoIssue(issues, 63, "Too many empty lines")
        issues_69 = [m for ln, m in issues if ln == 69]
        self.assertTrue(
            any("preceded by 1 or 2 empty lines" in m or "Too many empty lines" in m for m in issues_69),
            f"Expected empty line issue on line 69. Got: {issues_69}"
        )
        self.assertIssue(issues, 75, "Header block must be exactly 80")
        self.assertIssue(issues, 77, "Header block must be exactly 80")
        self.assertNoIssue(issues, 78, "Header block must be exactly 80")
        self.assertNoIssue(issues, 80, "Header block must be exactly 80")
        self.assertNoIssue(issues, 84, "Header block must be preceded by 1 or 2 empty lines")
        self.assertNoIssue(issues, 90, "No code between this comment and previous comment block")
        self.assertIssue(issues, 95, "Comment contains grammatical articles ('a', 'an', 'the')")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 13, "Header block must be exactly 80")
        self.assertNoIssue(issues_non_strict, 15, "Header block must be preceded by 1 or 2 empty lines")
        self.assertNoIssue(issues_non_strict, 75, "Header block must be exactly 80")
        self.assertNoIssue(issues_non_strict, 77, "Header block must be exactly 80")
        self.assertNoIssue(issues_non_strict, 44, "Lines inside header block must begin with '# '")
        self.assertNoIssue(issues_non_strict, 45, "Lines inside header block must begin with '# '")
        self.assertNoIssue(issues_non_strict, 46, "Lines inside header block must begin with '# '")
        self.assertNoIssue(issues_non_strict, 47, "Lines inside header block must begin with '# '")
        self.assertNoIssue(issues_non_strict, 56, "Too many empty lines")

    def test_single_header_block(self):
        """Ensure single header block separator doesn't incorrectly flag subsequent lines"""
        self.write_script(
            "#!/bin/bash\n"
            "\n"
            "################################################################################\n"
            "\n"
            "echo 2\n"                                              # Line 5: Passes
            "# Normal comment\n"                                    # Line 6: Passes
            "echo 3\n"                                              # Line 7: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 5, "Lines inside header block must begin with '# '")
        self.assertNoIssue(issues, 6, "Lines inside header block must begin with '# '")
        self.assertNoIssue(issues, 7, "Lines inside header block must begin with '# '")

    def test_shebang_spacing(self):
        """Enforce empty line after shebang"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"                                              # Line 2: Fails (missing empty line after shebang)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Empty line required after shebang")

        self.write_script(
            "#!/bin/bash\n"
            "# Comment right after shebang\n"                       # Line 2: Fails (empty line required after shebang)
            "echo 1\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Empty line required after shebang")

        self.write_script(
            "#!/bin/bash\n"
            "\n"                                                    # Line 2: Passes
            "echo 1\n"                                              # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Empty line required after shebang")
        self.assertNoIssue(issues, 3, "Empty line required after shebang")

    def test_header_before_code(self):
        """Enforce header length rules even before first line of code is encountered"""
        self.write_script(
            "#!/bin/bash\n"
            "\n"
            "#####\n"                                               # Line 3: Fails (header block too short)
            "echo 1\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Header block must be exactly 80")

    def test_comment_edge_cases(self):
        """Enforce comment indentation rules and closing block edge cases"""
        self.write_script(
            "#!/bin/bash\n"
            "    ( ( if [[ 1 == 1 ]]; then\n"
            "\n"
            "          # Comment aligned with badly indented code\n" # Line 4: Passes
            "          while [[ 2 == 2 ]]; do\n"                    # Line 5: Fails (code indentation)
            "            sleep 1\n"                                 # Line 6: Fails (code indentation)
            "          done\n"                                      # Line 7: Fails (code indentation)
            "        fi\n"
            "    ) ) &\n"
            "\n"
            "    # Misaligned comment with correct code\n"          # Line 11: Fails (comment indentation)
            "  echo \"correct indent\"\n"
            "\n"
            "        echo \"deep\"\n"
            "  # Correctly aligned comment\n"                       # Line 15: Passes
            "  echo \"shallow\"\n"
            "\n"
            "echo foo\n"
            "\n"
            "    2> >( while IFS='' read -r line; do\n"
            "\n"
            "            # comment 1\n"                             # Line 22: Passes
            "            if [[ -n \"${line}\" \\\n"
            "              && ( \"${trace-}\" != \"true\" || ! \"${line}\" =~ ^\\+ ) ]]; then\n"
            "              log 4 \"${line}\";\n"
            "\n"
            "            # comment 2\n"                             # Line 27: Fails (comment is 12, next is 10)
            "          fi\n"
            "\n"
            "    # comment 3\n"                                     # Line 30: Passes
            "        done ) || true\n"
            "\n"
            "echo foo\n"
            "\n"
            "func_a() {\n"
            "  echo 1\n"
            "\n"
            "  # Comment before closing brace\n"                    # Line 38: Passes (comment indentation valid)
            "  # Another comment\n"                                 # Line 39: Passes (comment indentation valid)
            "}\n"
            "\n"
            "echo foo\n"
            "\n"
            "# Comment ending in backslash \\\n"                    # Line 44: Passes
            "VAR_A=1\n"                                             # Line 45: Fails (uppercase user-configurable)
            "local_var=2 \\\n"
            "  ${#arr[@]}\n"
            "bad_var=3 \\ \n"                                       # Line 48: Fails (trailing whitespace after \)
            "  ${#arr[@]}\n"
            "\n"
            "echo foo\n"
            "\n"
            "a=1 # comment 1\n"
            "b=2 # comment 2\n"                                     # Line 54: Passes
            "c=3 # comment 3\n"                                     # Line 55: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "STYLE: Comment indentation mismatch")
        self.assertIssue(issues, 5, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 6, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 7, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 11, "STYLE: Comment indentation mismatch")
        self.assertNoIssue(issues, 15, "STYLE: Comment indentation mismatch")
        self.assertNoIssue(issues, 22, "STYLE: Comment indentation mismatch")
        self.assertIssue(issues, 27, "STYLE: Comment indentation mismatch")
        self.assertNoIssue(issues, 30, "STYLE: Comment indentation mismatch")
        self.assertNoIssue(issues, 38, "Comment indentation mismatch")
        self.assertNoIssue(issues, 39, "Comment indentation mismatch")
        self.assertNoIssue(issues, 44, "Trailing whitespace after line-continuation")
        self.assertIssue(issues, 45, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertIssue(issues, 45, "Variable assignment block is not alphabetically sorted")
        self.assertIssue(issues, 48, "Trailing whitespace after line-continuation backslash")
        self.assertNoIssue(issues, 54, "No code between this comment")
        self.assertNoIssue(issues, 55, "No code between this comment")

    def test_output_punctuation(self):
        """Enforce punctuation rules in output statements, with specific exemptions"""
        self.write_script(
            "#!/bin/bash\n"
            "printf \"Success.\\n\"\n"                              # Line 2: Fails (trailing period)
            "printf \"Waiting...\\n\"\n"                            # Line 3: Passes (ellipsis allowed)
            "log 3 \"Done.\"\n"                                     # Line 4: Fails (trailing period in log)
            "log 2 \"Loading...\"\n"                                # Line 5: Passes (ellipsis allowed)
            "echo \"Failed.\"\n"                                    # Line 6: Fails (trailing period in echo)
            "echo \"Working...\"\n"                                 # Line 7: Passes
            "\n"
            "echo \"Go to http://example.com.\"\n"                  # Line 9: Fails (trailing period in terminal output with URL)
            "\n"
            "log 7 \"stop_action skipping.\"\n"                     # Line 11: Fails (trailing period in terminal output)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Terminal output ends with trailing period")
        self.assertNoIssue(issues, 3, "Terminal output ends with trailing period")
        self.assertIssue(issues, 4, "Terminal output ends with trailing period")
        self.assertNoIssue(issues, 5, "Terminal output ends with trailing period")
        self.assertIssue(issues, 6, "Terminal output ends with trailing period")
        self.assertNoIssue(issues, 7, "Terminal output ends with trailing period")
        self.assertIssue(issues, 9, "Terminal output ends with trailing period")
        self.assertIssue(issues, 11, "trailing period")

    def test_strict_mode(self):
        """Enforce strict mode declarations"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 0, "Missing strict mode declarations")

        # Verify valid strict mode declarations pass
        self.write_script(
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "echo 1\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "Missing strict mode declarations")

        # Verify strict mode declarations split across lines pass
        self.write_script(
            "#!/bin/bash\n"
            "set -e\n"
            "set -u -o pipefail\n"
            "echo 1\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "Missing strict mode declarations")

        # Verify POSIX sh scripts do not require pipefail
        self.write_script(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf 1\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "Missing strict mode declarations")

    def test_naked_readonly(self):
        """Flag naked readonly declarations, allowing specific delayed assignments or guards"""
        self.write_script(
            "#!/bin/bash\n"
            "readonly bad_var\n"                                    # Line 2: Fails (naked readonly)
            "readonly bar=\"\"\n"                                   # Line 3: Passes (initialized)
            "[[ -n \"${foo-}\" ]]\n"
            "readonly foo\n"                                        # Line 5: Passes (guarded by check above)
            "read -r var1 var2 < file\n"
            "readonly var1 var2\n"                                  # Line 7: Passes (both initialized by read)
            "(( math_init = 1 ))\n"
            "readonly math_init\n"                                  # Line 9: Passes (initialized by math)
            "for loop_init in 1 2; do echo 1; done\n"
            "readonly loop_init\n"                                  # Line 11: Passes (initialized by for loop)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Naked readonly declaration leaves")
        self.assertNoIssue(issues, 3, "Naked readonly declaration")
        self.assertNoIssue(issues, 5, "Naked readonly declaration")
        self.assertNoIssue(issues, 7, "Naked readonly declaration")
        self.assertNoIssue(issues, 9, "Naked readonly declaration")
        self.assertNoIssue(issues, 11, "Naked readonly declaration")

        self.write_script(
            "#!/bin/bash\n"
            "CONFIG_VALS=1\n"
            "if true; then\n"
            "  readonly CONFIG_VALS\n"                              # Line 4: Passes (variable was assigned earlier)
            "fi\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "Naked readonly declaration")

        self.write_script(
            "#!/bin/bash\n"
            "CONFIG_VALS=1\n"
            "readonly CONFIG_VALS\n"                                # Line 3: Passes (variable was initialized)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "Naked readonly")

        self.write_script(
            "#!/bin/bash\n"
            "config_vals=\"${CONFIG_VALS:?}\"\n"
            "readonly CONFIG_VALS\n"                                # Line 3: Passes (initialized by parameter expansion)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "Naked readonly declaration leaves intention unclear")

    def test_array_spacing(self):
        """Enforce spacing in array initializations"""
        self.write_script(
            "#!/bin/bash\n"
            "my_arr=(\"a\" \"b\")\n"                                # Line 2: Fails (missing spacing both ends)
            "my_arr=( \"a\" \"b\" )\n"                              # Line 3: Passes
            "empty_arr=()\n"                                        # Line 4: Passes (empty array allowed)
            "my_arr=( \"a\" \"b\")\n"                               # Line 5: Fails (missing spacing end)
            "my_arr=(\"a\" \"b\" )\n"                               # Line 6: Fails (missing spacing start)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing spaces inside array initialization")
        self.assertNoIssue(issues, 3, "Missing spaces inside array initialization")
        self.assertNoIssue(issues, 4, "Missing spaces inside array initialization")
        self.assertIssue(issues, 5, "Missing space before closing parenthesis of array")
        self.assertIssue(issues, 6, "Missing space after array initialization start")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 2, "Missing spaces inside array initialization")
        self.assertNoIssue(issues_non_strict, 5, "Missing space before closing parenthesis of array")
        self.assertNoIssue(issues_non_strict, 6, "Missing space after array initialization start")

    def test_awk_complex_strings(self):
        """Test complex string handling in awk commands"""
        self.write_script(
            "#!/bin/bash\n"
            "awk '{print $1 \"|\" $2}'\n"                           # Line 2: Passes (does not throw operator errors)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Line wrapped after operator")

    def test_trailing_semicolon(self):
        """Flag unnecessary trailing semicolons"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1;\n"                                             # Line 2: Fails (unnecessary trailing semicolon)
            "awk '{print 1;}'\n"                                    # Line 3: Passes (inside awk string)
            "case $i in *) echo 1 ;; esac\n"                        # Line 4: Passes (esac line or ;;)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Unnecessary trailing semicolon")
        self.assertNoIssue(issues, 3, "Unnecessary trailing semicolon")
        self.assertNoIssue(issues, 4, "Unnecessary trailing semicolon")

    def test_uppercase_readonly(self):
        """Enforce readonly modifier for uppercase variables"""
        self.write_script(
            "#!/bin/bash\n"
            "CONST_A=\"value\"\n"                                   # Line 2: Fails (uppercase user configurable and not readonly)
            "readonly MY_CONST2=\"value\"\n"                        # Line 3: Fails (uppercase user configurable)
            "export VAR_A=\"value\"\n"                              # Line 4: Fails (uppercase user configurable)
            "SC_VAR=\"value\"\n"                                    # Line 5: Passes (SC_ exception)
            "STANDALONE=\"val\"\n"                                  # Line 6: Fails (uppercase user-configurable)
            "readonly STANDALONE\n"
            "MULTI1=\"1\"\n"                                        # Line 8: Fails (uppercase user-configurable)
            "MULTI2=\"2\"\n"                                        # Line 9: Fails (uppercase user-configurable)
            "readonly MULTI1 MULTI2 \\\n"
            "  MULTI3\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertIssue(issues, 2, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 3, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertNoIssue(issues, 3, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 4, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertNoIssue(issues, 4, "UPPERCASE but lacks 'readonly' modifier")
        self.assertNoIssue(issues, 5, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertNoIssue(issues, 5, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 6, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertNoIssue(issues, 6, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 8, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertNoIssue(issues, 8, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 9, "UPPERCASE. Is this really user-configurable parameter?")
        self.assertNoIssue(issues, 9, "UPPERCASE but lacks 'readonly' modifier")

    def test_inline_function_state(self):
        """Verify state is properly managed for inline functions"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() { echo 1; }\n"
            "var=1\n"                                               # Line 3: Passes (fails if state leaks)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "SCOPE: Variable 'var' assigned in function")

    def test_string_stripping_single_quotes(self):
        """Verify single-quoted strings are properly stripped"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  local a='\\' b=2 c='x'\n"
            "  b=3\n"                                               # Line 4: Passes (because b is local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'b' assigned in function")

    def test_get_color(self):
        """Verify color mapping for issue categories"""
        self.assertEqual(get_color('SAFETY'), C_RED)
        self.assertEqual(get_color('WARNING'), C_RED)
        self.assertEqual(get_color('DEAD CODE'), C_YELLOW)
        self.assertEqual(get_color('SCOPE'), C_YELLOW)
        self.assertEqual(get_color('COMPLEXITY'), C_CYAN)
        self.assertEqual(get_color('NOTICE'), C_CYAN)
        self.assertEqual(get_color('STYLE'), C_BLUE)
        self.assertEqual(get_color('SHFMT'), C_BLUE)
        self.assertEqual(get_color('UNKNOWN_CAT'), C_RESET)

    def test_complexity(self):
        """Flag overly complex or long functions and subshells"""
        long_func = "long_func() {\n" + "".join([f"  echo {i}\n" for i in range(60)]) + "}\n"
        complex_func = "complex_func() {\n" + "".join([f"  if [[ {i} == 1 ]]; then echo {i}; fi\n" for i in range(20)]) + "}\n"
        main_func = "main() {\n" + "".join([f"  if [[ {i} == 1 ]]; then echo {i}; fi\n" for i in range(20)]) + "".join([f"  echo {i}\n" for i in range(60)]) + "}\n"
        long_subshell = "(\n" + "".join([f"  echo {i}\n" for i in range(30)]) + ")\n"
        complex_subshell = "VAR=$(\n" + "".join([f"  if [[ {i} == 1 ]]; then echo {i}; fi\n" for i in range(15)]) + ")\n"
        long_complex_subshell = "(\n" + "".join([f"  echo {i}\n" for i in range(30)]) + "  if [[ 1 == 1 ]]; then echo 1; fi\n  if [[ 2 == 2 ]]; then echo 2; fi\n)\n"

        self.write_script(
            "#!/bin/bash\n"
            f"{long_func}"                                          # Line 2: Fails (caught via lines)
            f"{complex_func}"                                       # Line 3: Fails (caught via complexity)
            f"{main_func}"                                          # Line 4: Passes (main function exempted)
            f"{long_subshell}"                                      # Passes (subshell > 20 lines but complexity < 2)
            f"{complex_subshell}"                                   # Fails (subshell complexity >= 10)
            f"{long_complex_subshell}"                              # Fails (subshell > 20 lines and complexity >= 2)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "COMPLEXITY: Function 'long_func' is 60 lines of code. Consider modularizing if possible.")
        self.assertIssue(issues, 64, "COMPLEXITY: Function 'complex_func' is too complex")
        self.assertNoIssue(issues, 86, "COMPLEXITY")
        self.assertNoIssue(issues, 168, "COMPLEXITY: Subshell monolith detected")
        self.assertIssue(issues, 200, "COMPLEXITY: Subshell monolith detected")
        self.assertIssue(issues, 217, "COMPLEXITY: Subshell monolith detected")

    def test_crlf(self):
        """Flag CRLF line endings"""
        self.write_script(
            "#!/bin/bash\r\n"
            "echo 1\r\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 0, "File uses CRLF")

    def test_trailing_whitespace(self):
        """Flag trailing whitespace"""
        self.write_script(
            "#!/bin/bash\n"
            "a=1 \n"                                                # Line 2: Fails (trailing whitespace)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Trailing whitespace")

    def test_bare_variables(self):
        """Flag bare variables outside braces, with specific contextual exemptions and evaluations"""
        self.write_script(
            "#!/bin/bash\n"
            "echo $var\n"                                           # Line 2: Fails (bare variable)
            "echo ${var}\n"                                         # Line 3: Passes
            "echo $_ \n"                                            # Line 4: Passes (standard global allowed)
            "\n"
            "sh -c 'echo $PPID'\n"                                  # Line 6: Fails (bare variable inside evaluated string)
            "\n"
            "arr=()\n"
            "idx=0\n"
            "echo \"${arr[$idx]}\"\n"                               # Line 10: Passes (bare var safe inside array index)
            "\n"
            "PATH=\"/bin:$PATH\"\n"                                 # Line 12: Fails (bare variable inside string)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Bare variable '$var'")
        self.assertNoIssue(issues, 3, "Bare variable")
        self.assertNoIssue(issues, 4, "Bare variable")
        self.assertIssue(issues, 6, "Bare variable '$PPID'")
        self.assertNoIssue(issues, 10, "Bare variable")
        self.assertIssue(issues, 12, "Bare variable '$PATH'")

    def test_single_quote_backslash(self):
        """Verify handling of backslashes in single quotes"""
        self.write_script(
            "#!/bin/bash\n"
            "var='\\'\n"
            "((1+1))\n"                                             # Line 3: Fails (missing spaces, verifies quote closed)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Missing spaces inside math block")

    def test_subshell_spacing(self):
        """Enforce spacing after subshell start and before closing parenthesis"""
        self.write_script(
            "#!/bin/bash\n"
            "a=$(cmd)\n"                                            # Line 2: Fails (missing spacing both ends)
            "b=$( cmd )\n"                                          # Line 3: Passes
            "\n"
            "diff <(echo 1) <( echo 2 )\n"                          # Line 5: Fails (missing space in first substitution)
            "diff <( echo 1 ) <( echo 2 )\n"                        # Line 6: Passes
            "\n"
            "c=\"$(echo 1)\"\n"                                     # Line 8: Fails (missing spacing both ends, inside quotes)
            "d=$(cmd )\n"                                           # Line 9: Fails (missing spacing start)
            "e=$( cmd)\n"                                           # Line 10: Fails (missing spacing end)
            "diff <(echo 1 ) <( echo 2)\n"                          # Line 11: Fails (missing spacing start, missing spacing end)
            "(cmd)\n"                                               # Line 12: Fails (missing spacing both ends)
            "( cmd )\n"                                             # Line 13: Passes
            "(cmd )\n"                                              # Line 14: Fails (missing spacing start)
            "( cmd)\n"                                              # Line 15: Fails (missing spacing end)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing spaces inside command substitution")
        self.assertNoIssue(issues, 3, "Missing spaces inside command substitution")
        self.assertIssue(issues, 5, "Missing spaces inside process substitution")
        self.assertNoIssue(issues, 6, "Missing spaces inside process substitution")
        self.assertIssue(issues, 8, "Missing spaces inside command substitution")
        self.assertIssue(issues, 9, "Missing space after command substitution start")
        self.assertIssue(issues, 10, "Missing space before closing parenthesis of command substitution")
        self.assertIssue(issues, 11, "Missing space after process substitution start")
        self.assertIssue(issues, 11, "Missing space before closing parenthesis of process substitution")
        self.assertIssue(issues, 12, "Missing spaces inside subshell")
        self.assertNoIssue(issues, 13, "Missing spaces inside subshell")
        self.assertIssue(issues, 14, "Missing space after subshell start")
        self.assertIssue(issues, 15, "Missing space before closing parenthesis of subshell")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 2, "Missing spaces inside command substitution")
        self.assertNoIssue(issues_non_strict, 5, "Missing spaces inside process substitution")
        self.assertNoIssue(issues_non_strict, 8, "Missing spaces inside command substitution")
        self.assertNoIssue(issues_non_strict, 9, "Missing space after command substitution start")
        self.assertNoIssue(issues_non_strict, 10, "Missing space before closing parenthesis of command substitution")
        self.assertNoIssue(issues_non_strict, 11, "Missing space after process substitution start")
        self.assertNoIssue(issues_non_strict, 11, "Missing space before closing parenthesis of process substitution")
        self.assertNoIssue(issues_non_strict, 12, "Missing spaces inside subshell")
        self.assertNoIssue(issues_non_strict, 14, "Missing space after subshell start")
        self.assertNoIssue(issues_non_strict, 15, "Missing space before closing parenthesis of subshell")

    def test_unparseable_syntax(self):
        """Flag unparseable syntax that disrupts static analysis"""
        self.write_script(
            "#!/bin/bash\n"
            "[ \"$(osx_version)\" \"$@\" ]\n"                       # Line 2: Fails (unparseable bash test command syntax)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Unparseable syntax detected")

    def test_math_spacing(self):
        """Enforce spacing inside math blocks and math expansions"""
        self.write_script(
            "#!/bin/bash\n"
            "((1+1))\n"                                             # Line 2: Fails (missing spacing)
            "(( 1+1 ))\n"                                           # Line 3: Passes
            "a=$((1+2))\n"                                          # Line 4: Fails (missing spaces inside math expansion)
            "((b=3))\n"                                             # Line 5: Fails (missing spaces inside math block)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing spaces inside math block")
        self.assertNoIssue(issues, 3, "Missing spaces inside math block")
        self.assertIssue(issues, 4, "Missing spaces inside math block")
        self.assertIssue(issues, 5, "Missing spaces inside math block")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 2, "Missing spaces inside math block")
        self.assertNoIssue(issues_non_strict, 4, "Missing spaces inside math block")
        self.assertNoIssue(issues_non_strict, 5, "Missing spaces inside math block")

    def test_indentation(self):
        """Enforce proper indentation"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "echo 1\n"                                              # Line 3: Fails (missing indent)
            "  echo 2\n"                                            # Line 4: Passes
            "   echo 3\n"                                           # Line 5: Fails (odd numbered indent)
            "  }\n"                                                 # Line 6: Fails (misaligned brace)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SHFMT: Structural mismatch")
        self.assertNoIssue(issues, 4, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 5, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 6, "SHFMT: Structural mismatch")

    def test_posix_functions(self):
        """Flag non-POSIX function declarations"""
        self.write_script(
            "#!/bin/bash\n"
            "function func_a() {\n"                                 # Line 2: Fails (non-POSIX 'function' keyword)
            "  echo 1\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Non-POSIX function declaration")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 2, "Non-POSIX function declaration")

    def test_case_indentation_bug(self):
        """Verify that indentation issues inside strings within case blocks are properly flagged"""
        self.write_script(
            "#!/bin/bash\n"
            "case \"$1\" in\n"
            "  foo)\n"
            "    pid=\"$(ps -eo pid,args \\\n"
            "        | awk -v str=\"foo\" '\\\n"                    # Line 5: Fails (structural mismatch: expected 6 spaces, got 8)
            "                tolower($0) ~ /pattern/ \\\n"          # Line 6: Passes (inside string literal)
            "                          && index($0, str) {print $1; exit}' )\"\n" # Line 7: Passes (inside string literal)
            "    ;;\n"
            "esac\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 5, "SHFMT: Structural mismatch")
        self.assertNoIssue(issues, 6, "SHFMT: Structural mismatch")
        self.assertNoIssue(issues, 7, "SHFMT: Structural mismatch")

    def test_dangerous_patterns(self):
        """Flag dangerous patterns like eval, chmod 777, and kill -9"""
        self.write_script(
            "#!/bin/bash\n"
            "curl x | bash\n"                                       # Line 2: Fails (dangerous piping)
            "eval $x\n"                                             # Line 3: Fails (eval detected)
            "chmod 777 file\n"                                      # Line 4: Fails (chmod 777 detected)
            "set -x\n"                                              # Line 5: Fails (xtrace detected)
            "if [[ 1 == 1 ]]; then\n"
            "  set -x\n"                                            # Line 7: Passes (conditional xtrace)
            "fi\n"
            "[[ -n $trace ]] && set -x\n"                           # Line 9: Passes (inline conditional xtrace)
            "kill -9 12345\n"                                       # Line 10: Fails (kill -9 detected)
            "kill -TERM 12345\n"                                    # Line 11: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Dangerous pattern detected")
        self.assertIssue(issues, 3, "'eval' command detected")
        self.assertIssue(issues, 4, "'chmod 777' detected")
        self.assertIssue(issues, 5, "'set -x' (xtrace) detected")
        self.assertNoIssue(issues, 7, "'set -x' (xtrace) detected")
        self.assertNoIssue(issues, 9, "'set -x' (xtrace) detected")
        self.assertIssue(issues, 10, "'kill -9' detected")
        self.assertNoIssue(issues, 11, "'kill -9' detected")

    def test_magic_numbers(self):
        """Flag magic numbers in logic or sleep commands, with specific exemptions"""
        self.write_script(
            "#!/bin/bash\n"
            "sleep 10\n"                                            # Line 2: Fails (magic number > 2)
            "sleep 1\n"                                             # Line 3: Passes (<= 2 is allowed)
            "if [[ $var -gt 42 ]]; then\n"                          # Line 4: Fails (magic number 42)
            "  echo 1\n"
            "fi\n"
            "if [[ $var == 255 ]]; then\n"                          # Line 7: Passes (255 is allowed exception)
            "  echo 1\n"
            "fi\n"
            "sleep 1492\n"                                          # Line 10: Passes (1492 is allowed exception)
            "\n"
            "log 7 \"Parsing\"\n"                                   # Line 12: Passes (logging level)
            "tput setaf 208\n"                                      # Line 13: Passes (terminal color code)
            "exit 127\n"                                            # Line 14: Passes (standard exit code)
            "kill -9 12345\n"                                       # Line 15: Passes (signal and pid)
            "\n"
            "if [[ $? -ne 4 ]]; then\n"                             # Line 17: Passes (evaluating exit code)
            "  exit 127\n"                                          # Line 18: Passes
            "fi\n"
            "\n"
            "days=$(( 100 / 60 / 24 ))\n"                           # Line 21: Passes (math numbers are exempt)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Magic number '10' detected")
        self.assertNoIssue(issues, 3, "Magic number")
        self.assertIssue(issues, 4, "Magic number '42' detected")
        self.assertNoIssue(issues, 7, "Magic number")
        self.assertNoIssue(issues, 10, "Magic number")
        self.assertNoIssue(issues, 12, "Magic number")
        self.assertNoIssue(issues, 13, "Magic number")
        self.assertNoIssue(issues, 14, "Magic number")
        self.assertNoIssue(issues, 15, "Magic number")
        self.assertNoIssue(issues, 17, "Magic number")
        self.assertNoIssue(issues, 18, "Magic number")
        self.assertNoIssue(issues, 21, "Magic number")

    def test_empty_line_between_assignments(self):
        """Flag empty lines between variable assignment sets"""
        self.write_script(
            "#!/bin/bash\n"
            "a=1\n"
            "\n"
            "b=2\n"                                                 # Line 4: Fails (empty line between assignment sets)
            "\n"
            "echo foo\n"
            "\n"
            "a_val=1\n"
            "if [[ 1 == 1 ]]; then\n"
            "  b_val=2\n"                                           # Line 10: Passes (assignment inside if block)
            "fi\n"
            "\n"
            "echo foo\n"
            "\n"
            "readonly d=1\n"
            "\n"
            "readonly e=2\n"                                        # Line 17: Fails (empty line between assignment sets)
            "readonly f=3\n"
            "\n"
            "VAR3=\"val3\"\n"
            "\n"
            "IFS=' ' read -r -a my_array <<< \"${VAR3}\"\n"         # Line 22: Passes (not assignment set)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "Empty line between variable assignment sets")
        self.assertNoIssue(issues, 10, "Empty line between variable assignment sets")
        self.assertIssue(issues, 17, "Empty line between variable assignment sets")
        self.assertNoIssue(issues, 22, "Empty line between variable assignment sets")

    def test_ban_echo(self):
        """Enforce use of printf instead of echo"""
        self.write_script(
            "#!/bin/bash\n"
            "echo \"Hello\"\n"                                      # Line 2: Fails (use printf instead of echo)
            "printf \"Hello\"\n"                                    # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use 'printf' instead of 'echo'")
        self.assertNoIssue(issues, 3, "Use 'printf' instead of 'echo'")

    def test_bracket_style(self):
        """Enforce use of double brackets in bash, but allow single brackets in sh"""
        self.write_script(
            "#!/bin/bash\n"
            "if [ 1 = 1 ]; then\n"                                  # Line 2: Fails (use [[ ]] instead of [ ])
            "  printf 1\n"
            "fi\n"
            "\n"
            "if [[ \"${1}\" == *\"--debug\"* ]]; then\n"            # Line 6: Passes (valid bash keyword test)
            "  printf 1\n"
            "fi\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use Bash keyword '[[ ... ]]'")
        self.assertNoIssue(issues, 2, "[SC2292]")
        self.assertNoIssue(issues, 6, "Use Bash keyword '[[ ... ]]' instead of POSIX '[ ... ]' tests.")

        self.write_script(
            "#!/bin/sh\n"
            "if [ 1 = 1 ]; then\n"                                  # Line 2: Passes (POSIX tests allowed in sh scripts)
            "    printf 1\n"
            "fi\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Use Bash keyword '[[ ... ]]' instead of POSIX '[ ... ]' tests.")

    def test_shellcheck_rules(self):
        """Verify essential ShellCheck rules mentioned in documentation are caught"""
        self.write_script(
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "foo() { false; }\n"
            "if foo; then printf 1; fi\n"                           # Line 4: Fails SC2310
            "printf \"%s\\n\" \"$(false)\"\n"                       # Line 5: Fails SC2312
            "printf \"%s\\n\" `date`\n"                             # Line 6: Fails SC2006
            "cat file.txt | grep foo\n"                             # Line 7: Fails SC2002
            "var=\"foo\"\n"
            "printf \"%s\\n\" $var\n"                               # Line 9: Fails SC2086
            "printf \"%s\\n\" \"$undefined_var\"\n"                 # Line 10: Fails SC2154
            "if [[ \"$var=foo\" ]]; then printf 1; fi\n"            # Line 11: Fails SC2078
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "[SC2310]")
        self.assertIssue(issues, 5, "[SC2312]")
        self.assertIssue(issues, 6, "[SC2006]")
        self.assertIssue(issues, 7, "[SC2002]")
        self.assertIssue(issues, 9, "[SC2248]")
        self.assertIssue(issues, 10, "[SC2154]")
        self.assertIssue(issues, 11, "[SC2157]")

    def test_suppressed_shellcheck_rules(self):
        """Verify redundant ShellCheck rules are suppressed"""
        self.write_script(
            "#!/bin/bash\n"
            "var=\"foo\"\n"
            "printf \"%s\\n\" \"${var}\"\n"                         # Line 3: Fails SC2250 natively, but suppressed
            "if [ \"$var\" == \"foo\" ]; then printf 1; fi\n"       # Line 4: Fails SC2292 natively, but suppressed
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "[SC2250]")
        self.assertNoIssue(issues, 4, "[SC2292]")
        self.assertIssue(issues, 4, "Use Bash keyword '[[ ... ]]'")

    def test_redirection(self):
        """Enforce POSIX redirection, consistent spacing, and positioning"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1 &> /dev/null\n"                                 # Line 2: Fails (non-POSIX '&>')
            "echo 1 >& file.log\n"                                  # Line 3: Fails (non-POSIX '>&')
            "echo 1 >/dev/null\n"                                   # Line 4: Fails (inconsistent spacing)
            "echo 1 > /dev/null \n"                                 # Line 5: Passes
            "( cmd ) >/dev/null\n"                                  # Line 6: Fails (inconsistent spacing)
            "|| true; } ) >/dev/null 2>&1 &\n"                      # Line 7: Fails (inconsistent spacing)
            "\n"
            "echo 1 >&2\n"                                          # Line 9: Passes (>&2 is POSIX standard)
            "custom_echo >&2 'Error'\n"                             # Line 10: Passes
            "\n"
            "val=\"$( <\"file.txt\" )\"\n"                          # Line 12: Passes (redirection immediately followed by quotes is acceptable)
            "\n"
            ">&2 echo \"error\"\n"                                  # Line 14: Fails (redirection before command)
            "echo \"success\" > /dev/null\n"                        # Line 15: Passes (redirection at end)
            "\n"
            "echo 1 2> error.log\n"                                 # Line 17: Passes
            "echo 1 2>error.log\n"                                  # Line 18: Fails (inconsistent spacing)
            "echo 1 > out.log 2>&1\n"                               # Line 19: Passes
            "cat < input.txt\n"                                     # Line 20: Passes
            "cat <input.txt\n"                                      # Line 21: Fails (inconsistent spacing)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Non-POSIX redirection '&>'")
        self.assertIssue(issues, 3, "Non-POSIX redirection '>&'")
        self.assertIssue(issues, 4, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 5, "Inconsistent redirection spacing")
        self.assertIssue(issues, 6, "Inconsistent redirection spacing")
        self.assertIssue(issues, 7, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 9, "Non-POSIX redirection")
        self.assertNoIssue(issues, 10, "Non-POSIX redirection")
        self.assertNoIssue(issues, 12, "Inconsistent redirection spacing")
        self.assertIssue(issues, 14, "Redirections should be placed at end")
        self.assertNoIssue(issues, 15, "Redirections should be placed at end")
        self.assertNoIssue(issues, 17, "Inconsistent redirection spacing")
        self.assertIssue(issues, 18, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 19, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 19, "Non-POSIX redirection")
        self.assertNoIssue(issues, 20, "Inconsistent redirection spacing")
        self.assertIssue(issues, 21, "Inconsistent redirection spacing")

        non_strict_issues = self.get_issues(strict=False)
        self.assertNoIssue(non_strict_issues, 4, "Inconsistent redirection spacing")
        self.assertNoIssue(non_strict_issues, 6, "Inconsistent redirection spacing")
        self.assertNoIssue(non_strict_issues, 7, "Inconsistent redirection spacing")
        self.assertNoIssue(non_strict_issues, 18, "Inconsistent redirection spacing")
        self.assertNoIssue(non_strict_issues, 21, "Inconsistent redirection spacing")
        self.assertIssue(non_strict_issues, 2, "Non-POSIX redirection '&>'")

    def test_nested_subshell_quotes(self):
        """Verify nested subshell quotes handling"""
        self.write_script(
            "#!/bin/bash\n"
            "IFS=' ' read -r -a my_arr <<< \"$( printf '%s\\n' \"${my_arr}\" | tr -d \"'\" )\"\n"
            "echo 1 >/dev/null\n"                                   # Line 3: Fails (inconsistent spacing)
            "custom_print 3 \"Error: Item failed\"\n"
            "echo 1 >/dev/null\n"                                   # Line 5: Fails (inconsistent spacing)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Inconsistent redirection spacing")
        self.assertIssue(issues, 5, "Inconsistent redirection spacing")

    def test_multi_line_edge_blocks(self):
        """Test multi-line block detection in edge cases"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  local id count\n"
            "  if [[ -n \"${id-}\" ]] \\\n"
            "    && kill -0 \"${id}\" > /dev/null 2>&1; then\n"     # Line 5: Fails (misses multi-line if)
            "    custom_print 7 \"Waiting...\"\n"                   # Line 6: Passes
            "  fi\n"
            "}\n"
            "func_b() {\n"
            "  if [[ -n \"${id-}\" ]] && ps -p \"${id}\" > /dev/null 2>&1 \\\n"
            "    && [[ \"$( ps -o comm= -p \"${id}\" )\" == *\"app_name\"* ]]; then\n" # Line 11: Fails (misses multi-line if)
            "      # Kill process\n"
            "      custom_print 6 \"Terminating...\"\n"             # Line 13: Passes
            "  fi\n"
            "}\n"
            "func_c() {\n"
            "  \"script.sh\" \\\n"
            "    2> >( while IFS='' read -r line; do\n"
            "            if [[ -n \"${line}\" \\\n"                 # Line 19: Fails (unsafe unbound check)
            "              && ( \"${flag-}\" != \"true\" || ! \"${line}\" =~ ^\\+ ) ]]; then\n" # Line 20: Fails (misses multi-line if)
            "              custom_print 4 \"${line}\";\n"           # Line 21: Fails (unnecessary trailing semicolon)
            "          fi\n"
            "        done ) || true\n"
            "}\n"
        )
        issues = self.get_issues()

        self.assertIssue(issues, 5, "Multi-line 'if' detected")
        self.assertIssue(issues, 11, "Multi-line 'if' detected")
        self.assertIssue(issues, 19, "Unsafe unbound check")
        self.assertIssue(issues, 20, "Multi-line 'if' detected")
        self.assertIssue(issues, 21, "Unnecessary trailing semicolon")
        self.assertNoIssue(issues, 6, "Missing indentation after block start")
        self.assertNoIssue(issues, 13, "Missing indentation after block start")
        self.assertNoIssue(issues, 21, "Missing indentation after block start")

    def test_awk_quoting(self):
        """Flag unsafe awk quoting"""
        self.write_script(
            "#!/bin/bash\n"
            "awk \"{print \\$1}\" file\n"                           # Line 2: Fails (unsafe awk quoting)
            "awk '{print $1}' file\n"                               # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Unsafe awk quoting")
        self.assertNoIssue(issues, 3, "Unsafe awk quoting")

    def test_dead_code_stdin_and_missing(self):
        """Verify dead code analysis with stdin and missing files"""
        pass
        stdin_content = b"FUNC_C() { echo 1; }\n"
        dead_issues = analyze_dead_code(['-', 'does_not_exist.sh'], stdin_content=stdin_content)

        flat_stdin = []
        for ln, msgs in dead_issues.get('-', {}).items():
            for m in msgs:
                flat_stdin.append((ln, m))

        self.assertIssue(flat_stdin, 1, "DEAD CODE: Function 'FUNC_C' is defined but never invoked.")
        self.assertNotIn('does_not_exist.sh', dead_issues)

    def test_dead_code(self):
        """Flag unused functions and globals"""
        self.write_script(
            "#!/bin/bash\n"
            "func_c() { echo 1; }\n"                                # Line 2: Fails (unused func)
            "FUNC_A() { echo 2; }\n"
            "GLOBAL_B=1\n"                                          # Line 4: Fails (unused global)
            "GLOBAL_A=2\n"
            "MATH_VAL=5\n"
            "ARR_A=(1 2 3)\n"
            "ARR_B=(a b c)\n"
            "GLOBAL_B=3\n"                                          # Line 9: Fails (unused global multiple assignment)
            "func_d() { echo 3; }\n"
            "export -f func_d\n"
            "export EXPORTED_VAR=1\n"
            "func_e() { echo 4; }\n"
            "trap \"func_e\" TERM\n"
        )

        script2 = os.path.join(os.getcwd(), 'test_dummy_2.sh')
        with open(script2, 'w', encoding='utf-8') as f:
            f.write(
                "#!/bin/bash\n"
                "FUNC_A\n"
                "echo \"${GLOBAL_A}\"\n"
                "(( MATH_VAL++ ))\n"
                "echo \"${#ARR_A[@]}\"\n"
                "echo \"${!ARR_B[@]}\"\n"
            )

        pass
        dead_issues = analyze_dead_code([self.test_script, script2])

        flat_file1 = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_file1.append((ln, m))

        flat_file2 = []
        for ln, msgs in dead_issues.get(script2, {}).items():
            for m in msgs:
                flat_file2.append((ln, m))

        self.assertIssue(flat_file1, 2, "DEAD CODE: Function 'func_c' is defined but never invoked.")
        self.assertIssue(flat_file1, 4, "DEAD CODE: Global variable 'GLOBAL_B' is assigned but never used")
        self.assertIssue(flat_file1, 9, "DEAD CODE: Global variable 'GLOBAL_B' is assigned but never used")

        flat_file1_str = str(flat_file1)
        self.assertNotIn("FUNC_A", flat_file1_str)
        self.assertNotIn("GLOBAL_A", flat_file1_str)
        self.assertNotIn("MATH_VAL", flat_file1_str)
        self.assertNotIn("ARR_A", flat_file1_str)
        self.assertNotIn("ARR_B", flat_file1_str)
        self.assertNotIn("func_d", flat_file1_str)
        self.assertNotIn("EXPORTED_VAR", flat_file1_str)
        self.assertNotIn("func_e", flat_file1_str)
        self.assertEqual(len(flat_file2), 0)

        if os.path.exists(script2):
            os.remove(script2)

    def test_portability_checks(self):
        """Flag non-portable bash features"""
        self.write_script(
            "#!/bin/bash\n"
            "declare -g my_var\n"                                   # Line 2: Fails (Bash 4)
            "declare -A my_arr\n"                                   # Line 3: Fails (Bash 4)
            "mapfile -t arr < file\n"                               # Line 4: Fails (Bash 4)
            "readarray arr < file\n"                                # Line 5: Fails (Bash 4)
            "sed -i 's/a/b/' file\n"                                # Line 6: Fails (GNU/BSD diff)
            "sed -E 's/a/b/' file > tmp && mv tmp file\n"           # Line 7: Passes
            "declare -r my_var=1\n"                                 # Line 8: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "WARNING: 'declare -g' or 'declare -A' detected")
        self.assertIssue(issues, 3, "WARNING: 'declare -g' or 'declare -A' detected")
        self.assertIssue(issues, 4, "WARNING: 'mapfile' or 'readarray' detected")
        self.assertIssue(issues, 5, "WARNING: 'mapfile' or 'readarray' detected")
        self.assertIssue(issues, 6, "WARNING: 'sed -i' detected")
        self.assertNoIssue(issues, 7, "WARNING: 'sed -i' detected")
        self.assertNoIssue(issues, 8, "WARNING: 'declare -g' or 'declare -A' detected")

    def test_variable_actions(self):
        """Verify variable action parsing"""
        self.write_script(
            "#!/bin/bash\n"
            "a=\"1\"\n"
            "a+=\"2\"\n"                                            # Line 3: Passes
            "b+=( \"3\" )\n"                                        # Line 4: Passes
            "c_func() {\n"
            "  local d\n"
            "  d+=\"4\"\n"                                          # Line 7: Passes (scope because of line 6)
            "  e+=\"5\"\n"                                          # Line 8: Fails (scope not local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "SCOPE")
        self.assertNoIssue(issues, 4, "SCOPE")
        self.assertNoIssue(issues, 7, "SCOPE")
        self.assertIssue(issues, 8, "SCOPE: Variable 'e' assigned in function")

    def test_extreme_edge_cases(self):
        """Verify parser handling of extreme edge cases"""
        self.write_script(
            "#!/bin/bash\n"
            "echo \"$( echo \\\"$( echo \\\\\\\"deeply nested\\\\\\\" )\\\" )\"\n"
            "echo $'ANSI C \\' quotes' > /dev/null\n"               # Line 3: Passes (ANSI C strings)
            "echo \"${var:-\\\"default\\\"}\" > /dev/null\n"        # Line 4: Passes (parameter expansion)
            "echo \"${var//\\\"/}\" > /dev/null\n"                  # Line 5: Passes (search/replace parameter expansion)
            "echo `echo \\\"backticks\\\"` > /dev/null\n"           # Line 6: Passes (backtick subshells)
            "cat <<EOF\n"
            "  \"quotes inside heredoc\" >/dev/null\n"              # Line 8: Passes (heredoc body)
            "EOF\n"
            "case $x in *) echo 1 ;; esac\n"                        # Line 10: Passes (trailing semicolons in case)
            "echo >/dev/null\n"                                     # Line 11: Fails (inconsistent spacing)
            "# comment with \" and '\n"
            "echo >/dev/null\n"                                     # Line 13: Fails (inconsistent spacing)
            "var=\"multi\n"
            "line\"\n"
            "echo >/dev/null\n"                                     # Line 16: Fails (inconsistent spacing)
            "var='single multi\n"
            "line'\n"
            "echo >/dev/null\n"                                     # Line 19: Fails (inconsistent spacing)
            "echo \\\"escaped\\\" >/dev/null\n"                     # Line 20: Fails (inconsistent spacing)
            "echo \\'escaped\\' >/dev/null\n"                       # Line 21: Fails (inconsistent spacing)
            "arr=( \\\"foo\\\" 'bar' )\n"
            "echo >/dev/null\n"                                     # Line 23: Fails (inconsistent spacing)
            "echo \"\\${var}\" >/dev/null\n"                        # Line 24: Fails (inconsistent spacing)
            "echo \"$(echo 'inner')\" >/dev/null\n"                 # Line 25: Fails (inconsistent spacing)
            "echo \"$(echo \\\"inner\\\")\" >/dev/null\n"           # Line 26: Fails (inconsistent spacing)
            "log 5 \"$( ( printf '%s\\n' \\\"IP: NAME:\\\" ) )\"\n"
            "echo >/dev/null\n"                                     # Line 28: Fails (inconsistent spacing)
            "test_euid=\"$( sudo -c 'printf \\\"trim\\\"' )\"\n"
            "echo >/dev/null\n"                                     # Line 30: Fails (inconsistent spacing)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 4, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 5, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 6, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 8, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 10, "Unnecessary trailing semicolon")
        self.assertIssue(issues, 11, "Inconsistent redirection spacing")
        self.assertIssue(issues, 13, "Inconsistent redirection spacing")
        self.assertIssue(issues, 16, "Inconsistent redirection spacing")
        self.assertIssue(issues, 19, "Inconsistent redirection spacing")
        self.assertIssue(issues, 20, "Inconsistent redirection spacing")
        self.assertIssue(issues, 21, "Inconsistent redirection spacing")
        self.assertIssue(issues, 23, "Inconsistent redirection spacing")
        self.assertIssue(issues, 24, "Inconsistent redirection spacing")
        self.assertIssue(issues, 25, "Inconsistent redirection spacing")
        self.assertIssue(issues, 26, "Inconsistent redirection spacing")
        self.assertIssue(issues, 28, "Inconsistent redirection spacing")
        self.assertIssue(issues, 30, "Inconsistent redirection spacing")

    def test_posix_sh_mode(self):
        """Verify POSIX sh mode compatibility checks"""
        self.write_script(
            "#!/bin/sh\n"
            "if [ 1 = 1 ]; then\n"                                  # Line 2: Passes (allowed in POSIX sh)
            "  printf 1\n"
            "fi\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Use Bash keyword '[[ ... ]]' instead of POSIX '[ ... ]' test.")

    def test_bash_string_equality(self):
        """Enforce double equals for bash string equality"""
        self.write_script(
            "#!/bin/bash\n"
            "if [[ \"$a\" = \"$b\" ]]; then\n"                      # Line 2: Fails (single '=' in bash condition)
            "  printf 1\n"
            "fi\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use '==' instead of '=' for string comparison inside Bash '[[ ... ]]'")

    def test_bash_increment_style(self):
        """Enforce bash increment style"""
        self.write_script(
            "#!/bin/bash\n"
            "count=0\n"
            "count=$(( count + 1 ))\n"                              # Line 3: Fails
            "count=$(( count - 1 ))\n"                              # Line 4: Fails
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "NOTICE: Use Bash arithmetic evaluation '(( count++ ))' or '(( count-- ))' for cleaner increments.")
        self.assertIssue(issues, 4, "NOTICE: Use Bash arithmetic evaluation '(( count++ ))' or '(( count-- ))' for cleaner increments.")

    def test_markdown_report_generation(self):
        """Verify markdown report generation"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
        )

        md_file = os.path.join(os.getcwd(), 'test_dummy-sh-report.md')
        if os.path.exists(md_file):
            os.remove(md_file)

        shellens_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shellens.py')
        result = subprocess.run(
            [sys.executable, shellens_path, '--markdown', self.test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(md_file))

        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(f"# Analysis Report: `{self.test_script}`", content)
            self.assertIn("Use 'printf' instead of 'echo'", content)

        os.remove(md_file)

    def test_dead_code_ast_structures(self):
        """Verify dead code analysis respects various AST structures and assignments"""
        pass
        self.write_script(
            "#!/bin/bash\n"
            "USED_VAR=1\n"
            "UNUSED_VAR=2\n"                                        # Line 3: Fails (used in quoted heredoc, therefore literal text)
            "cat << EOF\n"
            "${USED_VAR}\n"
            "EOF\n"
            "cat << 'EOF'\n"
            "${UNUSED_VAR}\n"
            "EOF\n"
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_issues.append((ln, m))
        self.assertIssue(flat_issues, 3, "DEAD CODE: Global variable 'UNUSED_VAR' is assigned but never used.")

        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  extra_params+=( \"${1}\" )\n"                        # Line 3: Fails (assigned but never used)
            "  readonly color_blue=\"$( tput setaf 4 2> /dev/null || true )\"\n" # Line 4: Fails (assigned but never used)
            "}\n"
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_issues.append((ln, m))
        self.assertIssue(flat_issues, 3, "DEAD CODE: Global variable 'extra_params' is assigned but never used.")
        self.assertIssue(flat_issues, 4, "DEAD CODE: Global variable 'color_blue' is assigned but never used.")

        self.write_script(
            "#!/bin/bash\n"
            "val=\"$( LC_ALL=C date )\"\n"                          # Line 2: Passes
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_issues.append((ln, m))
        self.assertNoIssue(flat_issues, 2, "DEAD CODE: Global variable 'LC_ALL' is assigned but never used.")

        self.write_script(
            "#!/bin/bash\n"
            "readonly fmt_bold=\"a\"; printf 1\n"                   # Line 2: Fails (assigned but never used)
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = [(ln, m) for ln, msgs in dead_issues.get(self.test_script, {}).items() for m in msgs]
        self.assertIssue(flat_issues, 2, "DEAD CODE: Global variable 'fmt_bold'")

        self.write_script(
            "#!/bin/bash\n"
            "extra_params+=( \"${1}\" )\n"                          # Line 2: Fails (assigned but never used)
            "readonly extra_params\n"
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = [(ln, m) for ln, msgs in dead_issues.get(self.test_script, {}).items() for m in msgs]
        self.assertIssue(flat_issues, 2, "DEAD CODE: Global variable 'extra_params'")

        self.write_script(
            "#!/bin/bash\n"
            "readonly fmt_underline=\"a\"\n"                        # Line 2: Fails (assigned but never used)
            "printf 1\n"
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = [(ln, m) for ln, msgs in dead_issues.get(self.test_script, {}).items() for m in msgs]
        self.assertIssue(flat_issues, 2, "DEAD CODE: Global variable 'fmt_underline'")

    def test_conditional_depth_string_collision(self):
        """Ensure 'if' inside string does not trick conditional depth tracker"""
        self.write_script(
            "#!/bin/bash\n"
            "echo \"I wonder if this breaks it\"\n"
            "set -x\n"                                              # Line 3: Fails (flagged for xtrace)
            "echo \"fi\"\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "'set -x' (xtrace) detected")

    def test_complex_array_index_assignment(self):
        """Ensure nested brackets in array assignments are tracked for scope"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  arr[${keys[0]}]=1\n"                                 # Line 3: Fails (assigned without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'arr' assigned in function")

    def test_multiple_assignments_same_line(self):
        """Ensure all variables on single line are checked for scope and environment overrides are ignored"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  var1=1 var2=2\n"                                     # Line 3: Fails (both assigned without local)
            "  var3=3 echo hi > /dev/null\n"                        # Line 4: Passes (environment override)
            "  local var4=4 var5=5\n"                               # Line 5: Passes
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'var1' assigned in function")
        self.assertIssue(issues, 3, "SCOPE: Variable 'var2' assigned in function")
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'var3' assigned in function")
        self.assertNoIssue(issues, 5, "SCOPE: Variable 'var4' assigned in function")
        self.assertNoIssue(issues, 5, "SCOPE: Variable 'var5' assigned in function")

    def test_declare_assignment_missed(self):
        """Document limitation where 'declare' and 'typeset' are not parsed as assignment prefixes"""
        self.write_script(
            "#!/bin/bash\n"
            "declare my_global=1\n"
        )
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_issues.append((ln, m))
        flat_str = str(flat_issues)
        self.assertIn("DEAD CODE: Global variable 'my_global'", flat_str)

    def test_for_loop_string_collision(self):
        """Verify 'for' inside string does not trigger scope check"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  custom_log 7 \"system detected, checking for dummy-tool\"\n" # Line 3: Passes (dummy not flagged)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "SCOPE: Variable 'dummy' assigned in function")

    def test_pure_assignment_line_continuation(self):
        """Enforce scope checks on pure assignments that end with line continuation"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  logline=\"$( printf '%s\\n' )\" \\\n"                # Line 3: Fails (assigned without local)
            "    | sed 's/a/b/'\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'logline' assigned in function")

    def test_multiline_string_for_loop_collision(self):
        """Verify 'for' inside multiline string does not trigger scope check"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  custom_log 5 \"Start message\\n\\\n"
            "    Looking for test_user ...\"\n"                     # Line 4: Passes (test_user not flagged)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'test_user' assigned in function")

    def test_array_assignment_not_pure(self):
        """Verify array assignments within larger statements are explicitly caught"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  dummy_array=( \"--dummy=DSID=${dummy_value}\" ) && echo 1\n" # Line 3: Fails (assigned without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'dummy_array' assigned in function")

    def test_conditional_local_declaration_leak(self):
        """Verify that local/readonly declarations inside conditionals do not permanently whitelist variable for rest of function scope"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  if [[ 1 == 1 ]]; then\n"
            "    cookie=1\n"                                        # Line 4: Passes (protected by readonly on line 5 via lookahead)
            "    readonly cookie\n"
            "  else\n"
            "    cookie=2\n"                                        # Line 7: Fails (readonly above was conditional, so it didn't whitelist)
            "  fi\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'cookie' assigned in function")
        self.assertIssue(issues, 7, "SCOPE: Variable 'cookie' assigned in function")

    def test_complex_parameter_expansions(self):
        """Verify parser does not crash on obscure but valid Bash syntax"""
        self.write_script(
            "#!/bin/bash\n"
            "echo \"${var//[0-9]/}\"\n"                             # Line 2: Passes (obscure but valid syntax)
            "echo \"${!prefix@}\"\n"
            "echo \"${var:-$(echo \\\"default\\\")}\"\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Bare variable")

    def test_dynamic_vs_lexical_scoping(self):
        """Verify that scoping logic correctly handles dynamic/lexical scoping nuances"""
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"
            "  local x=1\n"
            "  func_b\n"
            "}\n"
            "func_b() {\n"
            "  x=2\n"                                               # Line 7: Fails (fails scope if strictly lexical)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 7, "SCOPE: Variable 'x' assigned in function without 'local' or 'readonly'.")

    def test_sed_i_cross_platform(self):
        """Catch sed -i variations that break cross-platform compatibility"""
        self.write_script(
            "#!/bin/bash\n"
            "run_elevated sed -i'' \"foo\" \"bar\"\n"               # Line 2: Fails (in-place replacement)
            "sed -i \"foo\" \"bar\"\n"                              # Line 3: Fails (in-place replacement)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "In-place replacement syntax is fundamentally incompatible")
        self.assertIssue(issues, 3, "In-place replacement syntax is fundamentally incompatible")

    def test_echo_in_string(self):
        """Echo usage inside single-quoted strings evaluated by shell"""
        self.write_script(
            "#!/bin/bash\n"
            "sh -c 'echo 1'\n"                                      # Line 2: Fails (echo inside evaluated string)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use 'printf' instead of 'echo'")

    def test_magic_number_math_exemption(self):
        """Numbers inside math expressions (like division) should not be flagged as logic magic numbers"""
        self.write_script(
            "#!/bin/bash\n"
            "days=$(( 100 / 60 / 24 ))\n"                           # Line 2: Passes (math numbers are exempt)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Magic number")

    def test_case_paren_exemption(self):
        """Verify case parenthesis exemption"""
        self.write_script(
            "#!/bin/bash\n"
            "case \"$a\" in\n"
            "  foo)\n"                                              # Line 3: Passes (case pattern parenthesis is exempt)
            "    echo 1;;\n"
            "esac\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "Missing space before closing parenthesis")

    def test_truncation_protection(self):
        """Enforce main() wrapper to protect against curl-pipe truncation"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 0, "No main() wrapper detected")

        self.write_script(
            "#!/bin/bash\n"
            "main() {\n"
            "  echo 1\n"
            "}\n"
            "main \"${@}\"\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "No main() wrapper detected")

    def test_command_shadowing(self):
        """Warn if user-defined functions shadow standard system binaries"""
        self.write_script(
            "#!/bin/bash\n"
            "ls() {\n"                                              # Line 2: Fails (shadows standard binary 'ls')
            "  echo 1\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Function 'ls' shadows standard system binary")

    def test_implicit_math(self):
        """Ban obsolete math commands 'let' and 'expr'"""
        self.write_script(
            "#!/bin/bash\n"
            "let a=1+1\n"                                           # Line 2: Fails (uses 'let')
            "expr 1 + 1\n"                                          # Line 3: Fails (uses 'expr')
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use Bash arithmetic")
        self.assertIssue(issues, 3, "Use POSIX arithmetic")

    def test_piped_while_read(self):
        """Prevent variables set in piped 'while read' loop from being lost in subshell"""
        self.write_script(
            "#!/bin/bash\n"
            "echo 1 | while read -r line; do\n"                     # Line 2: Fails (piped into while read)
            "  echo 1\n"
            "done\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Avoid piping into 'while read'")

    def test_obsolete_commands(self):
        """Ban obsolete commands like 'egrep', 'fgrep', and 'which'"""
        self.write_script(
            "#!/bin/bash\n"
            "egrep 'a' file\n"                                      # Line 2: Fails (uses 'egrep')
            "fgrep 'a' file\n"                                      # Line 3: Fails (uses 'fgrep')
            "which cmd\n"                                           # Line 4: Fails (uses 'which')
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use 'grep -E' instead of 'egrep'")
        self.assertIssue(issues, 3, "Use 'grep -F' instead of 'fgrep'")
        self.assertIssue(issues, 4, "Use 'command -v' instead of 'which'")

    def test_inefficient_grep_awk(self):
        """Detect inefficient pipelines piping 'grep' into 'awk'"""
        self.write_script(
            "#!/bin/bash\n"
            "grep 'foo' file | awk '{print $1}'\n"                  # Line 2: Fails (inefficient grep to awk)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Inefficient grep to awk pipeline")

    def test_empty_case_fallback(self):
        """Require explicit action in case statement fallback pattern '*)'"""
        self.write_script(
            "#!/bin/bash\n"
            "case \"$1\" in\n"
            "  *)\n"                                                # Line 3: Fails (case fallback '*)
            "    ;;\n"
            "esac\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Case fallback '*)' should contain explicit exit, return, or log command")

        issues_non_strict = self.get_issues(strict=False)
        self.assertNoIssue(issues_non_strict, 3, "Case fallback '*)' should contain explicit exit, return, or log command")

    def test_background_job_notice(self):
        """Warn about background processes that might become orphans"""
        self.write_script(
            "#!/bin/bash\n"
            "sleep 10 &\n"                                          # Line 2: Fails (background process launched)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Background process launched")

    def test_dynamic_command_warning(self):
        """Warn about dynamic command execution posing security risk when info flag is on"""
        self.write_script(
            "#!/bin/bash\n"
            "pkg_mgr=\"apt-get\"\n"
            "\"${pkg_mgr}\" install nginx\n"                        # Line 3: Fails under info (command executed from variable)
            "if \"${logging:-false}\"; then\n"                      # Line 4: Passes (idiomatic boolean evaluation)
            "  echo 1\n"
            "fi\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "NOTICE: Dynamic command execution detected")
        self.assertNoIssue(issues, 4, "Dynamic command execution detected")


class TestShellensCLI(unittest.TestCase):
    """Test CLI functionality"""
    def setUp(self):
        """Set up test environment"""
        self.shellens_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shellens.py')
        self.temp_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.orig_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)

    def tearDown(self):
        """Clean up test environment"""
        os.chdir(self.orig_cwd)
        self.temp_dir.cleanup()

    def test_strict_flag(self):
        """Verify strict flag behavior"""
        valid_file = "test_valid_strict.sh"
        with open(valid_file, "w", encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -euo pipefail\nLONG_VAR=\"This line is exactly eighty-five characters long, which is too long for strict mode.\"\n")

        env = os.environ.copy()
        env['NO_COLOR'] = '1'

        # Without --strict, it should pass length check
        result_normal = subprocess.run([sys.executable, self.shellens_path, valid_file], capture_output=True, check=False, text=True, env=env)
        self.assertNotIn("Code line exceeds 80 characters", result_normal.stdout)

        # With --strict, it should fail length
        result_strict = subprocess.run([sys.executable, self.shellens_path, '--strict', valid_file], capture_output=True, check=False, text=True, env=env)
        self.assertIn("Code line exceeds 80 characters", result_strict.stdout)

        os.remove(valid_file)

    def test_info_flag(self):
        """Verify info flag behavior"""
        valid_file = "test_valid_info.sh"
        with open(valid_file, "w", encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -euo pipefail\nUPPER_VAR=1\nprintf \"%s\\\\n\" \"$UPPER_VAR\"\n")

        env = os.environ.copy()
        env['NO_COLOR'] = '1'

        # Without --info, notices are hidden
        result_normal = subprocess.run([sys.executable, self.shellens_path, valid_file], capture_output=True, check=False, text=True, env=env)
        self.assertNotIn("UPPERCASE", result_normal.stdout)

        # With --info, notices appear
        result_info = subprocess.run([sys.executable, self.shellens_path, '--info', valid_file], capture_output=True, check=False, text=True, env=env)
        self.assertIn("UPPERCASE", result_info.stdout)

        os.remove(valid_file)

    def test_help_flag(self):
        """Verify help flag output"""
        for flag in ['--help', '-h']:
            result = subprocess.run([sys.executable, self.shellens_path, flag], capture_output=True, check=False, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Usage: shellens", result.stdout)

    def test_version_flag(self):
        """Verify version flag output"""
        for flag in ['--version', '-v']:
            result = subprocess.run([sys.executable, self.shellens_path, flag], capture_output=True, check=False, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn(f"Shellens v{__version__}", result.stdout)

    def test_no_arguments(self):
        """Verify behavior without arguments"""
        result = subprocess.run([sys.executable, self.shellens_path], capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage: shellens", result.stdout)

    def test_unknown_flag(self):
        """Verify behavior with unknown flags"""
        result = subprocess.run([sys.executable, self.shellens_path, '--unknown'], capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: Unknown option '--unknown'", result.stderr)

        result2 = subprocess.run([sys.executable, self.shellens_path, '--foo', '-bar'], capture_output=True, check=False, text=True)
        self.assertEqual(result2.returncode, 1)
        self.assertIn("Error: Unknown option '--foo'", result2.stderr)

    def test_file_not_found(self):
        """Verify behavior when file is not found"""
        result = subprocess.run([sys.executable, self.shellens_path, 'does_not_exist.sh'], capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: File does_not_exist.sh not found", result.stderr)
        self.assertNotIn("Perfect! No formatting, style, or dead code issues found", result.stdout)

    def test_mixed_valid_and_missing_files(self):
        """Verify behavior with mixed valid and missing files"""
        valid_file = os.path.join(os.getcwd(), 'dummy_valid.sh')
        with open(valid_file, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nprintf 1\n")

        result = subprocess.run([sys.executable, self.shellens_path, valid_file, 'does_not_exist.sh'], capture_output=True, check=False, text=True)
        os.remove(valid_file)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: File does_not_exist.sh not found", result.stderr)
        self.assertNotIn("Perfect! No formatting, style, or dead code issues found in", result.stdout)

    def test_directory_passed_as_script(self):
        """Verify behavior when directory is passed and scripts are extracted"""
        test_dir = os.path.join(os.getcwd(), 'dummy_dir')
        if not os.path.exists(test_dir):
            os.mkdir(test_dir)

        dummy_script = os.path.join(test_dir, 'dummy.sh')
        with open(dummy_script, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -euo pipefail\nmain() {\n  printf 1\n}\nmain\n")

        result = subprocess.run([sys.executable, self.shellens_path, test_dir], capture_output=True, check=False, text=True)
        os.remove(dummy_script)
        os.rmdir(test_dir)

        self.assertEqual(result.returncode, 0)
        self.assertIn("Perfect! No formatting, style, or dead code issues found", result.stdout)

    def test_unreadable_file(self):
        """Verify behavior with unreadable file"""
        unreadable_file = os.path.join(os.getcwd(), 'unreadable.sh')
        with open(unreadable_file, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\necho 1\n")
        os.chmod(unreadable_file, 0o000)

        result = subprocess.run([sys.executable, self.shellens_path, unreadable_file], capture_output=True, check=False, text=True)
        os.chmod(unreadable_file, 0o644)
        os.remove(unreadable_file)

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"Error: File {unreadable_file} is not readable", result.stderr)

    def test_binary_file_handling(self):
        """Verify behavior with binary file"""
        binary_file = os.path.join(os.getcwd(), 'dummy.bin')
        with open(binary_file, 'wb') as f:
            f.write(b'\x80\x81\x82\x83')

        result = subprocess.run([sys.executable, self.shellens_path, binary_file], capture_output=True, check=False, text=True)
        os.remove(binary_file)

        self.assertEqual(result.returncode, 1)
        self.assertIn("not valid UTF-8", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_double_dash_terminator(self):
        """Verify double dash terminator handling"""
        weird_file = os.path.join(os.getcwd(), '-weird_name.sh')
        with open(weird_file, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\necho 1\n")

        result = subprocess.run([sys.executable, self.shellens_path, '--', weird_file], capture_output=True, check=False, text=True)
        os.remove(weird_file)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Use 'printf' instead of 'echo'", result.stdout)
        self.assertNotIn("Unknown option", result.stdout)

    def test_duplicate_flags(self):
        """Verify behavior with duplicate flags"""
        test_file = os.path.join(os.getcwd(), 'dummy_cli_test.sh')
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nmain() { printf 1; }\nmain\n")
        result = subprocess.run([sys.executable, self.shellens_path, '--info', '--info', test_file], capture_output=True, check=False, text=True)
        os.remove(test_file)
        self.assertEqual(result.returncode, 0)

    def test_stdin_redirects_with_empty_args(self):
        """Verify stdin redirects with empty arguments"""
        result = subprocess.run([sys.executable, self.shellens_path], input="printf 1\n", capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage: shellens", result.stdout)

    def test_wildcard_globbing(self):
        """Verify wildcard globbing support"""
        file1 = os.path.join(os.getcwd(), 'test_glob_1.sh')
        file2 = os.path.join(os.getcwd(), 'test_glob_2.sh')
        with open(file1, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nmain() { printf 1; }\nmain\n")
        with open(file2, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nmain() { printf 2; }\nmain\n")

        glob_pattern = os.path.join(os.getcwd(), 'test_glob_*.sh')
        result = subprocess.run([sys.executable, self.shellens_path, glob_pattern], capture_output=True, check=False, text=True)

        os.remove(file1)
        os.remove(file2)

        self.assertEqual(result.returncode, 0)
        self.assertIn("Perfect! No formatting, style, or dead code issues found in", result.stdout)
        self.assertIn("test_glob_1.sh", result.stdout)
        self.assertIn("test_glob_2.sh", result.stdout)

    def test_stdin_linting(self):
        """Verify stdin linting"""
        code = "#!/bin/bash\necho 1\n"
        result = subprocess.run([sys.executable, self.shellens_path, '-'], input=code, capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Use 'printf' instead of 'echo'", result.stdout)
        self.assertIn("<stdin>", result.stdout)

    def test_no_color_flag(self):
        """Verify no-color flag disables ANSI colors"""
        test_file = os.path.join(os.getcwd(), 'dummy_color.sh')
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\necho 1\n")

        result = subprocess.run([sys.executable, self.shellens_path, '--no-color', test_file], capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('\033[', result.stdout)

        env = os.environ.copy()
        env['NO_COLOR'] = '1'
        result_env = subprocess.run([sys.executable, self.shellens_path, test_file], env=env, capture_output=True, check=False, text=True)
        self.assertNotIn('\033[', result_env.stdout)

        os.remove(test_file)


class TestCodeQuality(unittest.TestCase):
    """Verify code quality using external linters"""
    def setUp(self):
        """Set up test environment"""
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.shellens_path = os.path.join(self.repo_root, 'shellens.py')
        self.test_shellens_path = os.path.join(self.repo_root, 'tests', 'test_shellens.py')

    def test_flake8(self):
        """Run flake8 linter"""
        config_path = os.path.join(self.repo_root, 'tests', '.flake8')
        result = subprocess.run(
            ['flake8', f'--config={config_path}', self.shellens_path, self.test_shellens_path],
            capture_output=True, check=False, text=True
        )
        self.assertEqual(result.returncode, 0, f"flake8 failed:\n{result.stdout}\n{result.stderr}")

    def test_pylint(self):
        """Run pylint linter"""
        rc_path = os.path.join(self.repo_root, 'tests', '.pylintrc')
        result = subprocess.run(
            ['pylint', f'--rcfile={rc_path}', self.shellens_path, self.test_shellens_path],
            capture_output=True, check=False, text=True
        )
        self.assertEqual(result.returncode, 0, f"pylint failed:\n{result.stdout}\n{result.stderr}")


if __name__ == '__main__':
    unittest.main()
