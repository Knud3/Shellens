import os
import subprocess
import sys
import unittest
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from shellens_regex import check_format, __version__

class TestShellens(unittest.TestCase):
    def setUp(self):
        self.test_script = os.path.join(os.getcwd(), 'test_dummy.sh')

    def tearDown(self):
        if os.path.exists(self.test_script):
            os.remove(self.test_script)

    def write_script(self, code):
        with open(self.test_script, 'w') as f:
            f.write(code)

    def get_issues(self):
        issues = check_format(self.test_script, verbose=True)
        flat = []
        if issues:
            for ln, msgs in issues.items():
                for m in msgs:
                    flat.append((ln, m))
        return flat

    def assertIssue(self, issues, line_num, substring):
        found = any(ln == line_num and substring in msg for ln, msg in issues)
        self.assertTrue(found, f"Expected issue '{substring}' on line {line_num}. Got: {[m for l, m in issues if l == line_num]}")

    def assertNoIssue(self, issues, line_num, substring):
        found = any(ln == line_num and substring in msg for ln, msg in issues)
        self.assertFalse(found, f"Did not expect issue '{substring}' on line {line_num}. Got: {[m for l, m in issues if l == line_num]}")

    def test_missing_space_parenthesis(self):
        # Flag missing space before closing parenthesis
        self.write_script(
            "#!/bin/bash\n"
            "my_array=( 1 2 3)\n"                                   # Line 2: Fails (missing space)
            "my_array=( 1 2 3 )\n"                                  # Line 3: Passes
            "awk 'length(str)'\n"                                   # Line 4: Passes (inside awk string)
            "case $x in *) ;;\n"                                    # Line 5: Passes (case statement)
            "(( x + 1 ))\n"                                         # Line 6: Passes (math block)
            "echo \")\"\n"                                          # Line 7: Passes (inside string)
            "my_array=(\n"                                          # Line 8: Passes
            "  1 2 3\n"                                             # Line 9: Passes
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

    def test_multi_line_if(self):
        # Test multi-line if statement detection
        self.write_script(
            "#!/bin/bash\n"
            "if [[ $a == 1 ]] \\\n"                                 # Line 2: Passes
            "  && [[ $b == 2 ]]; then\n"                            # Line 3: Fails (then on same line as condition end)
            "  echo 1\n"                                            # Line 4: Passes
            "fi\n"                                                  # Line 5: Passes
            "if [[ $a == 1 ]] \\\n"                                 # Line 6: Passes
            "  && [[ $b == 2 ]]\n"                                  # Line 7: Passes
            "then\n"                                                # Line 8: Passes (then on its own line)
            "  echo 2\n"                                            # Line 9: Passes
            "fi\n"                                                  # Line 10: Passes
            "if [[ $a == 1 ]]; then\n"                              # Line 11: Passes (single line condition)
            "  echo 3\n"                                            # Line 12: Passes
            "fi\n"                                                  # Line 13: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Multi-line 'if' detected")
        self.assertNoIssue(issues, 8, "Multi-line 'if' detected")
        self.assertNoIssue(issues, 11, "Multi-line 'if' detected")

    def test_unsafe_unbound(self):
        # Flag unsafe unbound variable checks
        self.write_script(
            "#!/bin/bash\n"
            "if [[ -z \"${var}\" ]]; then echo 1; fi\n"             # Line 2: Fails (unsafe unbound check)
            "if [[ -z \"${var-}\" ]]; then echo 2; fi\n"            # Line 3: Passes (safe check)
            "if [[ -n \"${var:-}\" ]]; then echo 3; fi\n"           # Line 4: Passes (safe check)
            "if [[ $var == 1 ]]; then echo 4; fi\n"                 # Line 5: Passes (not -z/-n)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Unsafe unbound check")
        self.assertNoIssue(issues, 3, "Unsafe unbound check")
        self.assertNoIssue(issues, 4, "Unsafe unbound check")
        self.assertNoIssue(issues, 5, "Unsafe unbound check")

    def test_alphabetical_sort(self):
        # Enforce alphabetical sorting in declaration blocks
        self.write_script(
            "#!/bin/bash\n"
            "b_var=1\n"                                             # Line 2: Fails (unsorted)
            "a_var=2\n"                                             # Line 3: Fails (unsorted)
            "\n"                                                    # Line 4: Passes (empty line breaks block)
            "c_var=3\n"                                             # Line 5: Passes
            "d_var=4\n"                                             # Line 6: Passes (sorted block)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "alphabetically sorted")
        self.assertNoIssue(issues, 5, "alphabetically sorted")

    def test_consecutive_printf(self):
        # Flag consecutive printf statements
        self.write_script(
            "#!/bin/bash\n"
            "printf \"a\"\n"                                        # Line 2: Fails (consecutive)
            "printf \"b\"\n"                                        # Line 3: Fails (consecutive)
            "printf \"c\"\n"                                        # Line 4: Fails (consecutive)
            "echo \"d\"\n"                                          # Line 5: Passes
            "printf \"e\"\n"                                        # Line 6: Passes
            "printf \"%s\" \"${arr[@]}\"\n"                         # Line 7: Passes
            "printf \"f\"\n"                                        # Line 8: Passes (due to array mapping above)
            "printf \"g\" >/dev/null\n"                             # Line 9: Passes
            "printf \"h\"\n"                                        # Line 10: Passes (due to redirection above)
            "printf \"i %d\" \"${#arr[@]}\"\n"                      # Line 11: Passes
            "printf \"j\"\n"                                        # Line 12: Passes (due to array mapping above)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Consecutive 'printf'")
        self.assertNoIssue(issues, 6, "Consecutive 'printf'")
        self.assertNoIssue(issues, 8, "Consecutive 'printf'")
        self.assertNoIssue(issues, 10, "Consecutive 'printf'")
        self.assertNoIssue(issues, 12, "Consecutive 'printf'")

    def test_scope(self):
        # Enforce local scope for variables assigned in functions
        self.write_script(
            "#!/bin/bash\n"
            "global_var=1\n"                                        # Line 2: Passes
            "my_func() {\n"                                         # Line 3: Passes
            "  local_var=2\n"                                       # Line 4: Fails (missing local)
            "  local local_ok=3\n"                                  # Line 5: Passes
            "  global_var=4\n"                                      # Line 6: Fails (shadowing global)
            "  verbosity=5\n"                                       # Line 7: Passes (INTENTIONAL_GLOBALS)
            "  (( math_var=6 ))\n"                                  # Line 8: Fails (assigned in math block)
            "  (( math_var2++ ))\n"                                 # Line 9: Fails (assigned in math block)
            "  read -r read_var < file\n"                           # Line 10: Fails (assigned via read)
            "  for loop_var in 1 2 3; do echo 1; done\n"            # Line 11: Fails (assigned via for loop)
            "  local ok_math ok_read ok_loop\n"                     # Line 12: Passes
            "  (( ok_math = 1 ))\n"                                 # Line 13: Passes (declared local above)
            "  read -r ok_read < file\n"                            # Line 14: Passes (declared local above)
            "  for ok_loop in 1; do echo 1; done\n"                 # Line 15: Passes (declared local above)
            "  USER=\"admin\"\n"                                    # Line 16: Passes (STANDARD_ENV_VARS exempted)
            "}\n"                                                   # Line 17: Passes
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

    def test_line_length(self):
        # Enforce maximum line length limit
        long_code = "if [[ $a == 1 && $b == 2 && $c == 3 && $d == 4 && $e == 5 && $f == 6 && $g == 7 ]]; then"
        long_string = "a=" + "1"*79
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

    def test_math_dollar(self):
        # Flag variable expansion with dollar sign in math context
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
        # Flag lines wrapped after operators
        self.write_script(
            "#!/bin/bash\n"
            "echo a | \\\n"                                         # Line 2: Fails (wrapped after operator)
            "  echo b\n"                                            # Line 3: Passes
            "echo c \\\n"                                           # Line 4: Passes
            "  | echo d\n"                                          # Line 5: Passes (operator at start of next line)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Line wrapped after operator")
        self.assertNoIssue(issues, 4, "Line wrapped after operator")

    def test_comments(self):
        # Enforce comment formatting rules
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"                                              # Line 2: Passes
            "# The bad comment.\n"                                  # Line 3: Fails (trailing period, article, no padding)
            "\n"                                                    # Line 4: Passes
            "# Good comment\n"                                      # Line 5: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Comment must be preceded by exactly one empty line")
        self.assertIssue(issues, 3, "articles")
        self.assertNoIssue(issues, 5, "Comment must be preceded by exactly one empty line")
        self.assertNoIssue(issues, 5, "articles")

    def test_strict_mode_missing(self):
        # Enforce strict mode declarations
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"                                              # Line 2: Fails (missing set -euo pipefail)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 0, "Missing strict mode declarations")

    def test_strict_mode_valid(self):
        # Verify valid strict mode declarations pass
        self.write_script(
            "#!/bin/bash\n"
            "set -euo pipefail\n"                                   # Line 2: Passes
            "echo 1\n"                                              # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "Missing strict mode declarations")

    def test_strict_mode_split(self):
        # Verify strict mode declarations split across lines pass
        self.write_script(
            "#!/bin/bash\n"
            "set -e\n"                                              # Line 2: Passes (errexit)
            "set -u -o pipefail\n"                                  # Line 3: Passes (nounset, pipefail)
            "echo 1\n"                                              # Line 4: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "Missing strict mode declarations")

    def test_strict_mode_posix(self):
        # Verify POSIX sh scripts do not require pipefail
        self.write_script(
            "#!/bin/sh\n"                                           # POSIX sh
            "set -eu\n"                                             # Line 2: Passes (POSIX doesn't require pipefail)
            "printf 1\n"                                            # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 0, "Missing strict mode declarations")

    def test_naked_readonly(self):
        # Flag naked readonly declarations
        self.write_script(
            "#!/bin/bash\n"
            "readonly bad_var\n"                                    # Line 2: Fails (naked readonly)
            "readonly bar=\"\"\n"                                   # Line 3: Passes (initialized)
            "[[ -n \"${foo-}\" ]]\n"                                # Line 4: Passes
            "readonly foo\n"                                        # Line 5: Passes (guarded by check above)
            "read -r var1 var2 < file\n"                            # Line 6: Passes
            "readonly var1 var2\n"                                  # Line 7: Passes (both initialized by read)
            "(( math_init = 1 ))\n"                                 # Line 8: Passes
            "readonly math_init\n"                                  # Line 9: Passes (initialized by math)
            "for loop_init in 1 2; do echo 1; done\n"               # Line 10: Passes
            "readonly loop_init\n"                                  # Line 11: Passes (initialized by for loop)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Naked readonly declaration leaves")
        self.assertNoIssue(issues, 3, "Naked readonly declaration leaves")
        self.assertNoIssue(issues, 5, "Naked readonly declaration leaves")
        self.assertNoIssue(issues, 7, "Naked readonly declaration leaves")
        self.assertNoIssue(issues, 9, "Naked readonly declaration leaves")
        self.assertNoIssue(issues, 11, "Naked readonly declaration leaves")

    def test_array_spacing(self):
        # Enforce spacing in array initializations
        self.write_script(
            "#!/bin/bash\n"
            "my_arr=(\"a\" \"b\")\n"                                # Line 2: Fails (missing spacing)
            "my_arr=( \"a\" \"b\" )\n"                              # Line 3: Passes
            "empty_arr=()\n"                                        # Line 4: Passes (empty array allowed)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing space after array initialization")
        self.assertNoIssue(issues, 3, "Missing space after array initialization")
        self.assertNoIssue(issues, 4, "Missing space after array initialization")

    def test_process_substitution_spacing(self):
        # Enforce spacing in process substitutions
        self.write_script(
            "#!/bin/bash\n"
            "diff <(echo 1) <( echo 2 )\n"                          # Line 2: Fails (missing space in first substitution)
            "diff <( echo 1 ) <( echo 2 )\n"                        # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing space before closing parenthesis")
        self.assertNoIssue(issues, 3, "Missing space before closing parenthesis")

    def test_awk_complex_strings(self):
        # Test complex string handling in awk commands
        self.write_script(
            "#!/bin/bash\n"
            "awk '{print $1 \"|\" $2}'\n"                           # Line 2: Passes (does not throw operator errors)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Line wrapped after operator")

    def test_trailing_semicolon(self):
        # Flag unnecessary trailing semicolons
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

    def test_heredoc(self):
        # Verify heredoc content handling
        self.write_script(
            "#!/bin/bash\n"
            "cat << 'EOF'\n"                                        # Line 2: Passes
            "  This is a very very long line inside a heredoc that exceeds 80 characters by a lot!\n" # Line 3: Passes (inside heredoc)
            "EOF\n"                                                 # Line 4: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "Code line exceeds 80")

    def test_heredoc_termination(self):
        # Verify heredoc termination marker detection
        self.write_script(
            "#!/bin/bash\n"
            "cat << EOF\n"                                          # Line 2: Passes (no dash, requires exact EOF at start of line)
            "  EOF\n"                                               # Line 3: Passes (indented EOF does NOT terminate heredoc)
            "  this is still inside heredoc but will exceed 80 chars if not treated as heredoc! this line is very very very long and exceeds 80 characters.\n" # Line 4: Passes (still inside heredoc)
            "EOF\n"                                                 # Line 5: Passes (terminates heredoc)
            "cat <<- EOF_DASH\n"                                    # Line 6: Passes (dash allows indented EOF)
            "\tEOF_DASH\n"                                          # Line 7: Passes (terminates heredoc)
            "  this is outside heredoc but will exceed 80 chars because heredoc closed! this line is very very very long and exceeds 80 characters.\n" # Line 8: Fails (outside heredoc)
            "cat << EOF_TRAIL\n"                                    # Line 9: Passes
            "EOF_TRAIL; echo 1\n"                                   # Line 10: Fails (trailing chars on marker)
            "EOF_TRAIL\n"                                           # Line 11: Passes (terminates heredoc)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "Code line exceeds 80 characters")
        self.assertIssue(issues, 8, "Code line exceeds 80 characters")
        self.assertIssue(issues, 10, "Heredoc termination marker")

    def test_escaped_backslash_local_scope(self):
        # Verify escaped backslashes do not break local scope tracking
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  local a=1\\\\\n"                                     # Line 3: Passes (ends with escaped backslash, does not continue local block)
            "  b=2\n"                                               # Line 4: Fails (flagged as scope issue)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "SCOPE: Variable 'b' assigned in function without 'local' or 'readonly'.")

    def test_uppercase_readonly(self):
        # Enforce readonly modifier for uppercase variables
        self.write_script(
            "#!/bin/bash\n"
            "MY_CONST=\"value\"\n"                                  # Line 2: Fails (uppercase user configurable and not readonly)
            "readonly MY_CONST2=\"value\"\n"                        # Line 3: Fails (uppercase user configurable)
            "export MY_VAR=\"value\"\n"                             # Line 4: Fails (uppercase user configurable)
            "SC_VAR=\"value\"\n"                                    # Line 5: Passes (SC_ exception)
            "STANDALONE=\"val\"\n"                                  # Line 6: Passes (due to line 7 readonly)
            "readonly STANDALONE\n"                                 # Line 7: Passes
            "MULTI1=\"1\"\n"                                        # Line 8: Passes (due to line 10)
            "MULTI2=\"2\"\n"                                        # Line 9: Passes (due to line 10)
            "readonly MULTI1 MULTI2 \\\n"                           # Line 10: Passes
            "  MULTI3\n"                                            # Line 11: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertIssue(issues, 2, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 3, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertNoIssue(issues, 3, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 4, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertNoIssue(issues, 4, "UPPERCASE but lacks 'readonly' modifier")
        self.assertNoIssue(issues, 5, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertNoIssue(issues, 5, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 6, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertNoIssue(issues, 6, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 8, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertNoIssue(issues, 8, "UPPERCASE but lacks 'readonly' modifier")
        self.assertIssue(issues, 9, "UPPERCASE. Is this really a user-configurable parameter?")
        self.assertNoIssue(issues, 9, "UPPERCASE but lacks 'readonly' modifier")

    def test_inline_function_state(self):
        # Verify state is properly managed for inline functions
        self.write_script(
            "#!/bin/bash\n"
            "my_func() { echo 1; }\n"                               # Line 2: Passes (inline function)
            "var=1\n"                                               # Line 3: Passes (fails if state leaks)
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "SCOPE: Variable 'var' assigned in function")

    def test_string_stripping_single_quotes(self):
        # Verify single-quoted strings are properly stripped
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  local a='\\' b=2 c='x'\n"                            # Line 3: Passes (a='\' is string, b=2 is var, c='x' is string)
            "  b=3\n"                                               # Line 4: Passes (because b is local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'b' assigned in function")

    def test_get_color(self):
        # Verify color mapping for issue categories
        from shellens_regex import get_color, C_RED, C_YELLOW, C_CYAN, C_BLUE, C_RESET
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
        # Flag overly complex or long functions
        long_func = "long_func() {\n" + "".join([f"  echo {i}\n" for i in range(60)]) + "}\n"
        complex_func = "complex_func() {\n" + "".join([f"  if [[ {i} == 1 ]]; then echo {i}; fi\n" for i in range(20)]) + "}\n"
        main_func = "main() {\n" + "".join([f"  if [[ {i} == 1 ]]; then echo {i}; fi\n" for i in range(20)]) + "".join([f"  echo {i}\n" for i in range(60)]) + "}\n"

        self.write_script(
            "#!/bin/bash\n"
            f"{long_func}"                                          # Line 2: Fails (caught via lines)
            f"{complex_func}"                                       # Line 3: Fails (caught via complexity)
            f"{main_func}"                                          # Line 4: Passes (main function exempted)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "COMPLEXITY: Function 'long_func' is 60 lines of code. Consider modularizing if possible.")
        self.assertIssue(issues, 64, "COMPLEXITY: Function 'complex_func' is too complex")
        self.assertNoIssue(issues, 86, "COMPLEXITY")

    def test_crlf(self):
        # Flag CRLF line endings
        self.write_script(
            "#!/bin/bash\r\n"
            "echo 1\r\n"                                            # Line 2: Fails (CRLF ending)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 0, "File uses CRLF")

    def test_trailing_whitespace(self):
        # Flag trailing whitespace
        self.write_script(
            "#!/bin/bash\n"
            "a=1 \n"                                                # Line 2: Fails (trailing whitespace)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Trailing whitespace")

    def test_bare_variables(self):
        # Flag bare variables outside braces
        self.write_script(
            "#!/bin/bash\n"
            "echo $var\n"                                           # Line 2: Fails (bare variable)
            "echo ${var}\n"                                         # Line 3: Passes
            "echo $_ \n"                                            # Line 4: Passes (standard global allowed)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Bare variable '$var'")
        self.assertNoIssue(issues, 3, "Bare variable")
        self.assertNoIssue(issues, 4, "Bare variable")

    def test_single_quote_backslash(self):
        # Verify handling of backslashes in single quotes
        self.write_script(
            "#!/bin/bash\n"
            "var='\\'\n"                                            # Line 2: Passes
            "((1+1))\n"                                             # Line 3: Fails (missing spaces, verifies quote closed)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Missing spaces inside math block")

    def test_subshell_spacing(self):
        # Enforce spacing after subshell start
        self.write_script(
            "#!/bin/bash\n"
            "a=$(cmd)\n"                                            # Line 2: Fails (missing spacing)
            "b=$( cmd )\n"                                          # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing space after subshell start")
        self.assertNoIssue(issues, 3, "Missing space after subshell start")

    def test_math_spacing(self):
        # Enforce spacing inside math blocks
        self.write_script(
            "#!/bin/bash\n"
            "((1+1))\n"                                             # Line 2: Fails (missing spacing)
            "(( 1+1 ))\n"                                           # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Missing spaces inside math block")
        self.assertNoIssue(issues, 3, "Missing spaces inside math block")

    def test_indentation(self):
        # Enforce proper indentation
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"                                         # Line 2: Passes
            "echo 1\n"                                              # Line 3: Fails (missing indent)
            "  echo 2\n"                                            # Line 4: Passes
            "   echo 3\n"                                           # Line 5: Fails (odd numbered indent)
            "  }\n"                                                 # Line 6: Fails (misaligned brace)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Missing indentation after block start")
        self.assertNoIssue(issues, 4, "Missing indentation after block start")
        self.assertIssue(issues, 5, "Odd-numbered indentation")
        self.assertIssue(issues, 6, "Misaligned closing brace")

    def test_posix_functions(self):
        # Flag non-POSIX function declarations
        self.write_script(
            "#!/bin/bash\n"
            "function my_func() {\n"                                # Line 2: Fails (non-POSIX 'function' keyword)
            "  echo 1\n"                                            # Line 3: Passes
            "}\n"                                                   # Line 4: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Non-POSIX function declaration")

    def test_dangerous_patterns(self):
        # Flag dangerous patterns like eval, chmod 777, and kill -9
        self.write_script(
            "#!/bin/bash\n"
            "curl x | bash\n"                                       # Line 2: Fails (dangerous piping)
            "eval $x\n"                                             # Line 3: Fails (eval detected)
            "chmod 777 file\n"                                      # Line 4: Fails (chmod 777 detected)
            "set -x\n"                                              # Line 5: Fails (xtrace detected)
            "if [[ 1 == 1 ]]; then\n"                               # Line 6: Passes (conditional block start)
            "  set -x\n"                                            # Line 7: Passes (conditional xtrace)
            "fi\n"                                                  # Line 8
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
        # Flag magic numbers in logic or sleep commands
        self.write_script(
            "#!/bin/bash\n"
            "sleep 10\n"                                            # Line 2: Fails (magic number > 2)
            "sleep 1\n"                                             # Line 3: Passes (<= 2 is allowed)
            "if [[ $var -gt 42 ]]; then\n"                          # Line 4: Fails (magic number 42)
            "  echo 1\n"
            "fi\n"
            "if [[ $var == 255 ]]; then\n"                          # Line 7: Passes (255 is an allowed exception)
            "  echo 1\n"
            "fi\n"
            "sleep 1492\n"                                          # Line 10: Passes (1492 is an allowed exception)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Magic number '10' detected")
        self.assertNoIssue(issues, 3, "Magic number")
        self.assertIssue(issues, 4, "Magic number '42' detected")
        self.assertNoIssue(issues, 7, "Magic number")
        self.assertNoIssue(issues, 10, "Magic number")

    def test_declaration_list_sorting(self):
        # Enforce alphabetical sorting in declaration lists
        self.write_script(
            "#!/bin/bash\n"
            "local b a\n"                                           # Line 2: Fails (unsorted variables)
            "local c d\n"                                           # Line 3: Passes (sorted variables)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Variables in declaration list")
        self.assertNoIssue(issues, 3, "Variables in declaration list")

    def test_empty_line_between_assignments(self):
        # Flag empty lines between variable assignment sets
        self.write_script(
            "#!/bin/bash\n"
            "a=1\n"                                                 # Line 2: Passes
            "\n"                                                    # Line 3: Passes
            "b=2\n"                                                 # Line 4: Fails (empty line between assignment sets)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "Empty line between variable assignment sets")

    def test_ban_echo_and_bracket(self):
        # Enforce use of printf and double brackets
        self.write_script(
            "#!/bin/bash\n"
            "echo \"Hello\"\n"                                      # Line 2: Fails (use printf instead of echo)
            "if [ 1 = 1 ]; then\n"                                  # Line 3: Fails (use [[ ]] instead of [ ])
            "  printf 1\n"                                          # Line 4: Passes
            "fi\n"                                                  # Line 5: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use 'printf' instead of 'echo'")
        self.assertIssue(issues, 3, "Use Bash keyword '[[ ... ]]'")
        self.assertNoIssue(issues, 3, "[SC2292]")

    def test_strict_redirection(self):
        # Enforce POSIX redirection and consistent spacing
        self.write_script(
            "#!/bin/bash\n"
            "echo 1 &> /dev/null\n"                                 # Line 2: Fails (non-POSIX '&>')
            "echo 1 >& file.log\n"                                  # Line 3: Fails (non-POSIX '>&')
            "echo 1 >/dev/null\n"                                   # Line 4: Fails (inconsistent spacing)
            "echo 1 > /dev/null \n"                                 # Line 5: Passes
            "( cmd ) >/dev/null\n"                                  # Line 6: Fails (inconsistent spacing)
            "|| true; } ) >/dev/null 2>&1 &\n"                      # Line 7: Fails (inconsistent spacing)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Non-POSIX redirection '&>'")
        self.assertIssue(issues, 3, "Non-POSIX redirection '>&'")
        self.assertIssue(issues, 4, "Inconsistent redirection spacing")
        self.assertNoIssue(issues, 5, "Inconsistent redirection spacing")
        self.assertIssue(issues, 6, "Inconsistent redirection spacing")
        self.assertIssue(issues, 7, "Inconsistent redirection spacing")

    def test_nested_subshell_quotes(self):
        # Verify nested subshell quotes handling
        self.write_script(
            "#!/bin/bash\n"
            "IFS=' ' read -r -a my_arr <<< \"$( printf '%s\\n' \"${my_arr}\" | tr -d \"'\" )\"\n" # Line 2: Passes
            "echo 1 >/dev/null\n"                                   # Line 3: Fails (inconsistent spacing)
            "custom_print 3 \"Error: Item failed\"\n"               # Line 4: Passes
            "echo 1 >/dev/null\n"                                   # Line 5: Fails (inconsistent spacing)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "Inconsistent redirection spacing")
        self.assertIssue(issues, 5, "Inconsistent redirection spacing")

    def test_multi_line_edge_blocks(self):
        # Test multi-line block detection in edge cases
        self.write_script(
            "#!/bin/bash\n"
            "func_a() {\n"                                          # Line 2: Passes
            "  local id count\n"                                    # Line 3: Passes
            "  if [[ -n \"${id-}\" ]] \\\n"                         # Line 4: Passes
            "    && kill -0 \"${id}\" > /dev/null 2>&1; then\n"     # Line 5: Fails (misses multi-line if)
            "    custom_print 7 \"Waiting...\"\n"                   # Line 6: Passes
            "  fi\n"                                                # Line 7: Passes
            "}\n"                                                   # Line 8: Passes
            "func_b() {\n"                                          # Line 9: Passes
            "  if [[ -n \"${id-}\" ]] && ps -p \"${id}\" > /dev/null 2>&1 \\\n" # Line 10: Passes
            "    && [[ \"$( ps -o comm= -p \"${id}\" )\" == *\"app_name\"* ]]; then\n" # Line 11: Fails (misses multi-line if)
            "      # Kill process\n"                                # Line 12: Passes
            "      custom_print 6 \"Terminating...\"\n"             # Line 13: Passes
            "  fi\n"                                                # Line 14: Passes
            "}\n"                                                   # Line 15: Passes
            "func_c() {\n"                                          # Line 16: Passes
            "  \"script.sh\" \\\n"                                  # Line 17: Passes
            "    2> >( while IFS='' read -r line; do\n"             # Line 18: Passes
            "            if [[ -n \"${line}\" \\\n"                 # Line 19: Fails (unsafe unbound check)
            "              && ( \"${flag-}\" != \"true\" || ! \"${line}\" =~ ^\\+ ) ]]; then\n" # Line 20: Fails (misses multi-line if)
            "              custom_print 4 \"${line}\";\n"           # Line 21: Fails (unnecessary trailing semicolon)
            "          fi\n"                                        # Line 22: Passes
            "        done ) || true\n"                              # Line 23: Passes
            "}\n"                                                   # Line 24: Passes
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
        # Flag unsafe awk quoting
        self.write_script(
            "#!/bin/bash\n"
            "awk \"{print \\$1}\" file\n"                           # Line 2: Fails (unsafe awk quoting)
            "awk '{print $1}' file\n"                               # Line 3: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Unsafe awk quoting")
        self.assertNoIssue(issues, 3, "Unsafe awk quoting")

    def test_simple_if(self):
        # Flag simple if statements and isolated 'then' impurities
        self.write_script(
            "#!/bin/bash\n"
            "if [[ 1 == 1 ]]\n"                                     # Line 2: Fails (simple if)
            "then\n"                                                # Line 3: Passes
            "  echo 1\n"                                            # Line 4: Passes
            "fi\n"                                                  # Line 5: Passes
            "if [[ 1 == 1 ]]; then\n"                               # Line 6: Passes
            "  echo 2\n"                                            # Line 7: Passes
            "fi\n"                                                  # Line 8: Passes
            "if [[ 2 == 2 ]] \\\n"                                  # Line 9: Passes (multi-line if)
            "  && [[ 3 == 3 ]]\n"                                   # Line 10: Passes
            "then # Some comment\n"                                 # Line 11: Fails (isolated 'then' has trailing comment)
            "  echo 3\n"                                            # Line 12: Passes
            "fi\n"                                                  # Line 13: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Simple 'if' detected")
        self.assertNoIssue(issues, 6, "Simple 'if' detected")
        self.assertIssue(issues, 11, "Isolated 'then' line contains trailing characters or comments")

    def test_comment_continuation(self):
        # Verify comment continuation handling and flag trailing whitespace after line continuation
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
            "\n"
            "# Comment ending in backslash \\\n"                    # Line 4: Passes
            "MY_VAR=1\n"                                            # Line 5: Passes (not parsed as comment)
            "local_var=2 \\\n"                                      # Line 6: Passes (line continuation with #)
            "  ${#arr[@]}\n"                                        # Line 7: Passes (has hash but is not comment)
            "bad_var=3 \\ \n"                                       # Line 8: Fails (trailing whitespace after \)
            "  ${#arr[@]}\n"                                        # Line 9: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "Trailing whitespace after line-continuation")
        self.assertIssue(issues, 5, "UPPERCASE")
        self.assertIssue(issues, 5, "Variable assignment block is not alphabetically sorted")
        self.assertIssue(issues, 8, "Trailing whitespace after line-continuation backslash")

    def test_array_assignment_scope(self):
        # Enforce local scope for array assignments in functions
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  arr[0]=1\n"                                          # Line 3: Fails (assigned without local)
            "  arr+=(\"a\")\n"                                      # Line 4: Fails (assigned without local)
            "  my_array=( \"--arg=1\" \"--arg=2\" )\n"              # Line 5: Fails (initialization without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'arr' assigned in function")
        self.assertIssue(issues, 4, "SCOPE: Variable 'arr' assigned in function")
        self.assertIssue(issues, 5, "SCOPE: Variable 'my_array' assigned in function")

    def test_advanced_comments(self):
        # Enforce advanced comment formatting rules
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"                                              # Line 2: Passes
            "\n"                                                    # Line 3: Passes
            "# Bad comment.\n"                                      # Line 4: Fails (trailing period)
            "\n"                                                    # Line 5: Passes
            "#######\n"                                             # Line 6: Fails (header length)
            "echo 2\n"                                              # Line 7: Passes
            "#####\n"                                               # Line 8: Fails (1 or 2 empty lines)
            "echo 3\n"                                              # Line 9: Passes
            "\n"                                                    # Line 10: Passes
            "# Loading something...\n"                              # Line 11: Fails (ellipsis in comment)
            "echo 4 # inline comment\n"                             # Line 12: Passes
            "# Following comment\n"                                 # Line 13: Passes (because previous was inline comment)
            "# var=1\n"                                             # Line 14: Passes (commented code)
            "# echo 5\n"                                            # Line 15: Passes (commented code)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 4, "Comment ends with a trailing period")
        self.assertIssue(issues, 6, "Header block must be exactly 80 '#' characters")
        self.assertIssue(issues, 8, "Header block must be preceded by 1 or 2 empty lines")
        self.assertIssue(issues, 11, "Comment ends with a trailing period")
        self.assertNoIssue(issues, 13, "Comment must be preceded by exactly one empty line")
        self.assertNoIssue(issues, 14, "No code between this comment")
        self.assertNoIssue(issues, 15, "No code between this comment")

    def test_printf_punctuation(self):
        # Enforce punctuation rules in printf statements
        self.write_script(
            "#!/bin/bash\n"
            "printf \"Success.\\n\"\n"                              # Line 2: Fails (trailing period)
            "printf \"Waiting...\\n\"\n"                            # Line 3: Passes (ellipsis allowed)
            "my_log 3 \"Done.\"\n"                                  # Line 4: Fails (trailing period in log)
            "custom_print 2 \"Loading...\"\n"                       # Line 5: Passes (ellipsis allowed)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Terminal output ends with a trailing period")
        self.assertNoIssue(issues, 3, "Terminal output ends with a trailing period")
        self.assertIssue(issues, 4, "Terminal output ends with a trailing period")
        self.assertNoIssue(issues, 5, "Terminal output ends with a trailing period")

    def test_dead_code_stdin_and_missing(self):
        # Verify dead code analysis with stdin and missing files
        from shellens_regex import analyze_dead_code
        stdin_content = b"UNUSED_FUNC() { echo 1; }\n"
        dead_issues = analyze_dead_code(['-', 'does_not_exist.sh'], stdin_content=stdin_content)

        flat_stdin = []
        for ln, msgs in dead_issues.get('-', {}).items():
            for m in msgs:
                flat_stdin.append((ln, m))

        self.assertIssue(flat_stdin, 1, "DEAD CODE: Function 'UNUSED_FUNC' is defined but never invoked.")
        self.assertNotIn('does_not_exist.sh', dead_issues)

    def test_dead_code(self):
        # Flag unused functions and globals
        self.write_script(
            "#!/bin/bash\n"
            "unused_func() { echo 1; }\n"                           # Line 2: Fails (unused func)
            "USED_FUNC() { echo 2; }\n"                             # Line 3: Passes (used in file 2)
            "UNUSED_GLOBAL=1\n"                                     # Line 4: Fails (unused global)
            "USED_GLOBAL_VAR=2\n"                                   # Line 5: Passes (used in file 2)
            "MATH_USED=5\n"                                         # Line 6: Passes (used in math context in file 2)
            "ARR_LEN_VAR=(1 2 3)\n"                                 # Line 7: Passes (used via length)
            "ARR_KEY_VAR=(a b c)\n"                                 # Line 8: Passes (used via keys)
        )

        script2 = os.path.join(os.getcwd(), 'test_dummy_2.sh')
        with open(script2, 'w') as f:
            f.write(
                "#!/bin/bash\n"
                "USED_FUNC\n"
                "echo \"${USED_GLOBAL_VAR}\"\n"
                "(( MATH_USED++ ))\n"
                "echo \"${#ARR_LEN_VAR[@]}\"\n"
                "echo \"${!ARR_KEY_VAR[@]}\"\n"
            )

        from shellens_regex import analyze_dead_code
        dead_issues = analyze_dead_code([self.test_script, script2])

        flat_file1 = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_file1.append((ln, m))

        flat_file2 = []
        for ln, msgs in dead_issues.get(script2, {}).items():
            for m in msgs:
                flat_file2.append((ln, m))

        self.assertIssue(flat_file1, 2, "DEAD CODE: Function 'unused_func' is defined but never invoked.")
        self.assertIssue(flat_file1, 4, "DEAD CODE: Global variable 'UNUSED_GLOBAL' is assigned but never used")

        flat_file1_str = str(flat_file1)
        self.assertNotIn("USED_FUNC", flat_file1_str)
        self.assertNotIn("USED_GLOBAL_VAR", flat_file1_str)
        self.assertNotIn("MATH_USED", flat_file1_str)
        self.assertNotIn("ARR_LEN_VAR", flat_file1_str)
        self.assertNotIn("ARR_KEY_VAR", flat_file1_str)
        self.assertEqual(len(flat_file2), 0)

        if os.path.exists(script2):
            os.remove(script2)

    def test_portability_checks(self):
        # Flag non-portable bash features
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
        # Verify variable action parsing
        self.write_script(
            "#!/bin/bash\n"
            "a=\"1\"\n"                                             # Line 2: Passes
            "a+=\"2\"\n"                                            # Line 3: Passes
            "b+=( \"3\" )\n"                                        # Line 4: Passes
            "c_func() {\n"                                          # Line 5: Passes
            "  local d\n"                                           # Line 6: Passes
            "  d+=\"4\"\n"                                          # Line 7: Passes (scope because of line 6)
            "  e+=\"5\"\n"                                          # Line 8: Fails (scope not local)
            "}\n"                                                   # Line 9: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "SCOPE")
        self.assertNoIssue(issues, 4, "SCOPE")
        self.assertNoIssue(issues, 7, "SCOPE")
        self.assertIssue(issues, 8, "SCOPE: Variable 'e' assigned in function")

    def test_extreme_edge_cases(self):
        # Verify parser handling of extreme edge cases
        self.write_script(
            "#!/bin/bash\n"
            "echo \"$( echo \\\"$( echo \\\\\\\"deeply nested\\\\\\\" )\\\" )\"\n" # Line 2: Passes (nested subshells)
            "echo $'ANSI C \\' quotes' > /dev/null\n"               # Line 3: Passes (ANSI C strings)
            "echo \"${var:-\\\"default\\\"}\" > /dev/null\n"        # Line 4: Passes (parameter expansion)
            "echo \"${var//\\\"/}\" > /dev/null\n"                  # Line 5: Passes (search/replace parameter expansion)
            "echo `echo \\\"backticks\\\"` > /dev/null\n"           # Line 6: Passes (backtick subshells)
            "cat <<EOF\n"                                           # Line 7: Passes (heredoc start)
            "  \"quotes inside heredoc\" >/dev/null\n"              # Line 8: Passes (heredoc body)
            "EOF\n"                                                 # Line 9: Passes (heredoc end)
            "case $x in *) echo 1 ;; esac\n"                        # Line 10: Passes (trailing semicolons in case)
            "echo >/dev/null\n"                                     # Line 11: Fails (inconsistent spacing)
            "# comment with \" and '\n"                             # Line 12: Passes
            "echo >/dev/null\n"                                     # Line 13: Fails (inconsistent spacing)
            "var=\"multi\n"                                         # Line 14: Passes
            "line\"\n"                                              # Line 15: Passes
            "echo >/dev/null\n"                                     # Line 16: Fails (inconsistent spacing)
            "var='single multi\n"                                   # Line 17: Passes
            "line'\n"                                               # Line 18: Passes
            "echo >/dev/null\n"                                     # Line 19: Fails (inconsistent spacing)
            "echo \\\"escaped\\\" >/dev/null\n"                     # Line 20: Fails (inconsistent spacing)
            "echo \\'escaped\\' >/dev/null\n"                       # Line 21: Fails (inconsistent spacing)
            "arr=( \\\"foo\\\" 'bar' )\n"                           # Line 22: Passes
            "echo >/dev/null\n"                                     # Line 23: Fails (inconsistent spacing)
            "echo \"\\${var}\" >/dev/null\n"                        # Line 24: Fails (inconsistent spacing)
            "echo \"$(echo 'inner')\" >/dev/null\n"                 # Line 25: Fails (inconsistent spacing)
            "echo \"$(echo \\\"inner\\\")\" >/dev/null\n"           # Line 26: Fails (inconsistent spacing)
            "log 5 \"$( ( printf '%s\\n' \\\"IP: NAME:\\\" ) )\"\n" # Line 27: Passes
            "echo >/dev/null\n"                                     # Line 28: Fails (inconsistent spacing)
            "test_euid=\"$( sudo -c 'printf \\\"trim\\\"' )\"\n"    # Line 29: Passes
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

    def test_comment_indentation(self):
        # Enforce comment indentation rules
        self.write_script(
            "#!/bin/bash\n"
            "    ( ( if [[ 1 == 1 ]]; then\n"                       # Line 2
            "\n"                                                    # Line 3
            "          # Comment aligned with badly indented code\n" # Line 4: Passes comment rule, SHFMT catches code
            "          while [[ 2 == 2 ]]; do\n"                    # Line 5: Fails (code indentation)
            "            sleep 1\n"                                 # Line 6: Fails (code indentation)
            "          done\n"                                      # Line 7: Fails (code indentation)
            "        fi\n"                                          # Line 8
            "    ) ) &\n"                                           # Line 9
            "\n"                                                    # Line 10
            "    # Misaligned comment with correct code\n"          # Line 11: Fails (comment indentation)
            "  echo \"correct indent\"\n"                           # Line 12: Passes
            "\n"                                                    # Line 13
            "        echo \"deep\"\n"                               # Line 14: Passes
            "  # Correctly aligned comment\n"                       # Line 15: Passes
            "  echo \"shallow\"\n"                                  # Line 16: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "STYLE: Comment indentation mismatch")
        self.assertIssue(issues, 5, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 6, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 7, "SHFMT: Structural mismatch")
        self.assertIssue(issues, 11, "STYLE: Comment indentation mismatch")
        self.assertNoIssue(issues, 15, "STYLE: Comment indentation mismatch")

    def test_closing_block_comments(self):
        # Verify comments before closing blocks
        self.write_script(
            "#!/bin/bash\n"
            "    2> >( while IFS='' read -r line; do\n"             # Line 2
            "\n"                                                    # Line 3
            "            # comment 1\n"                             # Line 4: Passes
            "            if [[ -n \"${line}\" \\\n"                 # Line 5
            "              && ( \"${trace-}\" != \"true\" || ! \"${line}\" =~ ^\\+ ) ]]; then\n" # Line 6
            "              log 4 \"${line}\";\n"                    # Line 7
            "\n"                                                    # Line 8
            "            # comment 2\n"                             # Line 9: Fails (comment is 12, next is 10)
            "          fi\n"                                        # Line 10
            "\n"                                                    # Line 11
            "    # comment 3\n"                                     # Line 12: Passes
            "        done ) || true\n"                              # Line 13
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "STYLE: Comment indentation mismatch")
        self.assertIssue(issues, 9, "STYLE: Comment indentation mismatch")
        self.assertNoIssue(issues, 12, "STYLE: Comment indentation mismatch")

    def test_comments_before_closing_brace(self):
        # Verify comments before closing braces
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  echo 1\n"
            "\n"
            "  # Comment before closing brace\n"                    # Line 5: Passes (comment indentation valid)
            "  # Another comment\n"                                 # Line 6: Passes (comment indentation valid)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 5, "Comment indentation mismatch")
        self.assertNoIssue(issues, 6, "Comment indentation mismatch")

    def test_posix_sh_mode(self):
        # Verify POSIX sh mode compatibility checks
        self.write_script(
            "#!/bin/sh\n"
            "if [ 1 = 1 ]; then\n"                                  # Line 2: Passes (allowed in POSIX sh)
            "  printf 1\n"                                          # Line 3: Passes (allowed in POSIX sh)
            "fi\n"                                                  # Line 4: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 2, "Use Bash keyword '[[ ... ]]' instead of POSIX '[ ... ]' test.")

    def test_bash_string_equality(self):
        # Enforce double equals for bash string equality
        self.write_script(
            "#!/bin/bash\n"
            "if [[ \"$a\" = \"$b\" ]]; then\n"                      # Line 2: Fails (single '=' in bash condition)
            "  printf 1\n"                                          # Line 3: Passes
            "fi\n"                                                  # Line 4: Passes
        )
        issues = self.get_issues()
        self.assertIssue(issues, 2, "Use '==' instead of '=' for string comparison inside Bash '[[ ... ]]'")

    def test_bash_increment_style(self):
        # Enforce bash increment style
        self.write_script(
            "#!/bin/bash\n"
            "count=0\n"                                             # Line 2: Passes
            "count=$(( count + 1 ))\n"                              # Line 3: Fails (suggest ++ instead)
            "count=$(( count - 1 ))\n"                              # Line 4: Fails (suggest -- instead)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "NOTICE: Use Bash arithmetic evaluation '(( count++ ))' for cleaner increments.")
        self.assertIssue(issues, 4, "NOTICE: Use Bash arithmetic evaluation '(( count-- ))' for cleaner increments.")

    def test_markdown_report_generation(self):
        # Verify markdown report generation
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"                                              # Line 2: Fails (uses echo instead of printf)
        )

        md_file = os.path.join(os.getcwd(), 'test_dummy-sh-report.md')
        if os.path.exists(md_file):
            os.remove(md_file)

        shellens_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shellens_regex.py')
        result = subprocess.run(
            [sys.executable, shellens_path, '--markdown', self.test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(md_file))

        with open(md_file, 'r') as f:
            content = f.read()
            self.assertIn(f"# Analysis Report: `{self.test_script}`", content)
            self.assertIn("Use 'printf' instead of 'echo'", content)

        os.remove(md_file)

    def test_verbose_flag(self):
        # Verify verbose flag output
        self.write_script(
            "#!/bin/bash\n"
            "MY_CONST=\"value\"\n"                                  # Line 2: Fails (verbose warns about configurable consts)
        )
        shellens_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shellens_regex.py')
        result = subprocess.run(
            [sys.executable, shellens_path, '--verbose', self.test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        self.assertIn("Is this really a user-configurable parameter?", result.stdout)

    def test_heredoc_variable_expansion_dead_code(self):
        # Verify dead code analysis respects heredoc variable expansion
        self.write_script(
            "#!/bin/bash\n"
            "USED_VAR=1\n"                                          # Line 2: Passes (used in open heredoc)
            "UNUSED_VAR=2\n"                                        # Line 3: Fails (used in quoted heredoc, therefore literal text)
            "cat << EOF\n"                                          # Line 4
            "${USED_VAR}\n"                                         # Line 5
            "EOF\n"                                                 # Line 6
            "cat << 'EOF'\n"                                        # Line 7
            "${UNUSED_VAR}\n"                                       # Line 8
            "EOF\n"                                                 # Line 9
        )

        from shellens_regex import analyze_dead_code
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_issues.append((ln, m))

        flat_str = str(flat_issues)
        self.assertIn("DEAD CODE: Global variable 'UNUSED_VAR'", flat_str)

    def test_nested_math_scopes(self):
        # Verify nested math scopes are tracked correctly
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"                                         # Line 2
            "  (( math_var = $(( math_inner + 1 )) ))\n"            # Line 3: Fails (math_var assigned)
            "}\n"                                                   # Line 4
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'math_var' assigned in function")
        self.assertNoIssue(issues, 3, "SCOPE: Variable 'math_inner' assigned in function")

    def test_conditional_depth_string_collision(self):
        # Ensure 'if' inside string does not trick conditional depth tracker
        self.write_script(
            "#!/bin/bash\n"
            "echo \"I wonder if this breaks it\"\n"                 # Line 2: Passes (word 'if' is in string)
            "set -x\n"                                              # Line 3: Fails (flagged for xtrace)
            "echo \"fi\"\n"                                         # Line 4: Passes (word 'fi' is in string)
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "'set -x' (xtrace) detected")

    def test_complex_array_index_assignment(self):
        # Ensure nested brackets in array assignments are tracked for scope
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  arr[${keys[0]}]=1\n"                                 # Line 3: Fails (assigned without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'arr' assigned in function")

    def test_multiple_assignments_same_line(self):
        # Ensure all variables on single line are checked for scope and environment overrides are ignored
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
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
        # Document limitation where 'declare' and 'typeset' are not parsed as assignment prefixes
        self.write_script(
            "#!/bin/bash\n"
            "declare my_global=1\n"                                 # Line 2: Passes (global assignment)
        )
        from shellens_regex import analyze_dead_code
        dead_issues = analyze_dead_code([self.test_script])
        flat_issues = []
        for ln, msgs in dead_issues.get(self.test_script, {}).items():
            for m in msgs:
                flat_issues.append((ln, m))
        flat_str = str(flat_issues)
        self.assertIn("DEAD CODE: Global variable 'my_global'", flat_str)

    def test_for_loop_string_collision(self):
        # Verify 'for' inside string does not trigger scope check
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  custom_log 7 \"system detected, checking for dummy-tool\"\n" # Line 3: Passes (dummy not flagged)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "SCOPE: Variable 'dummy' assigned in function")

    def test_pure_assignment_line_continuation(self):
        # Enforce scope checks on pure assignments that end with line continuation
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  logline=\"$( printf '%s\\n' )\" \\\n"                # Line 3: Fails (assigned without local)
            "    | sed 's/a/b/'\n"
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'logline' assigned in function")

    def test_singleline_command_substitution_scope(self):
        # Enforce scope checks on variables assigned via command substitution
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  message=\"$( printf '%b\\n' \"${2}\" | sed 's/^[[:space:]]*//' )\"\n" # Line 3: Fails (assigned without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'message' assigned in function")

    def test_multiline_string_assignment_scope(self):
        # Enforce scope checks on variables assigned across multiple lines with trailing backslash
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  logline=\"$( printf '%s\\n' \"${2}\" \\\n"           # Line 3: Fails (assigned without local)
            "    | sed -e ':a' -e 'N;$!ba' )\"\n"                   # Line 4: Passes
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'logline' assigned in function")

    def test_multi_line_comments_without_headers(self):
        # Flag multi-line comments that are not enclosed in header blocks
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
            "\n"
            "# This is line one\n"                                  # Line 4: Passes
            "# This is line two\n"                                  # Line 5: Fails (multi-line comment not in header block)
            "echo 2\n"
            "\n"
            "################################################################################\n" # Line 8
            "# This is line one in header\n"                        # Line 9: Passes
            "# This is line two in header\n"                        # Line 10: Passes
            "################################################################################\n" # Line 11
        )
        issues = self.get_issues()
        self.assertIssue(issues, 5, "Multi-line comments are not allowed")
        self.assertNoIssue(issues, 9, "Multi-line comments are not allowed")
        self.assertNoIssue(issues, 10, "Multi-line comments are not allowed")

    def test_contiguous_inline_comments(self):
        # Verify contiguous inline comments do not trigger spacing or contiguous block errors
        self.write_script(
            "#!/bin/bash\n"
            "a=1 # comment 1\n"                                     # Line 2: Passes
            "b=2 # comment 2\n"                                     # Line 3: Passes
            "c=3 # comment 3\n"                                     # Line 4: Passes
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 3, "No code between this comment")
        self.assertNoIssue(issues, 4, "No code between this comment")

    def test_too_many_empty_lines(self):
        # Enforce no more than one empty line between blocks of code
        self.write_script(
            "#!/bin/bash\n"
            "echo 1\n"
            "\n"
            "\n"
            "echo 2\n"                                              # Line 5: Fails (2 empty lines before it)
            "\n"
            "################################################################################\n" # Line 7: Passes (1 empty line)
            "# Header\n"
            "################################################################################\n"
            "\n"
            "\n"
            "################################################################################\n" # Line 12: Passes (2 empty lines allowed before header)
            "# Header 2\n"
            "################################################################################\n"
            "\n"
            "\n"
            "\n"
            "################################################################################\n" # Line 18: Fails (3 empty lines)
            "# Header 3\n"
            "################################################################################\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 5, "Too many empty lines")
        self.assertNoIssue(issues, 7, "Too many empty lines")
        self.assertNoIssue(issues, 12, "Too many empty lines")
        issues_18 = [m for l, m in issues if l == 18]
        self.assertTrue(
            any("preceded by 1 or 2 empty lines" in m or "Too many empty lines" in m for m in issues_18),
            f"Expected empty line issue on line 18. Got: {issues_18}"
        )

    def test_multiline_string_for_loop_collision(self):
        # Verify 'for' inside multiline string does not trigger scope check
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  custom_log 5 \"Start message\\n\\\n"
            "    Looking for dummy_user ...\"\n"                    # Line 4: Passes (dummy_user not flagged)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'dummy_user' assigned in function")

    def test_array_assignment_not_pure(self):
        # Verify array assignments within larger statements are explicitly caught
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  dummy_array=( \"--dummy=DSID=${dummy_value}\" ) && echo 1\n" # Line 3: Fails (assigned without local)
            "}\n"
        )
        issues = self.get_issues()
        self.assertIssue(issues, 3, "SCOPE: Variable 'dummy_array' assigned in function")

    def test_conditional_local_declaration_leak(self):
        # Verify that local/readonly declarations inside conditionals do not permanently whitelist variable for rest of function scope
        self.write_script(
            "#!/bin/bash\n"
            "my_func() {\n"
            "  if [[ 1 == 1 ]]; then\n"                             # Line 3: Passes (conditional depth increases)
            "    cookie=1\n"                                        # Line 4: Passes (protected by readonly on line 5 via lookahead)
            "    readonly cookie\n"                                 # Line 5: Passes (declared readonly)
            "  else\n"                                              # Line 6: Passes (else branch)
            "    cookie=2\n"                                        # Line 7: Fails (readonly above was conditional, so it didn't whitelist)
            "  fi\n"                                                # Line 8: Passes (conditional depth decreases)
            "}\n"
        )
        issues = self.get_issues()
        self.assertNoIssue(issues, 4, "SCOPE: Variable 'cookie' assigned in function")
        self.assertIssue(issues, 7, "SCOPE: Variable 'cookie' assigned in function")

class TestShellensCLI(unittest.TestCase):
    def setUp(self):
        self.shellens_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shellens_regex.py')

    def test_help_flag(self):
        # Verify help flag output
        for flag in ['--help', '-h']:
            result = subprocess.run([sys.executable, self.shellens_path, flag], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Usage: shellens", result.stdout)

    def test_version_flag(self):
        # Verify version flag output
        for flag in ['--version', '-v']:
            result = subprocess.run([sys.executable, self.shellens_path, flag], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn(f"Shellens v{__version__}", result.stdout)

    def test_no_arguments(self):
        # Verify behavior without arguments
        result = subprocess.run([sys.executable, self.shellens_path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage: shellens", result.stdout)

    def test_unknown_flag(self):
        # Verify behavior with unknown flags
        result = subprocess.run([sys.executable, self.shellens_path, '--unknown'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: Unknown option '--unknown'", result.stdout)

        result2 = subprocess.run([sys.executable, self.shellens_path, '--foo', '-bar'], capture_output=True, text=True)
        self.assertEqual(result2.returncode, 1)
        self.assertIn("Error: Unknown option '--foo'", result2.stdout)

    def test_file_not_found(self):
        # Verify behavior when file is not found
        result = subprocess.run([sys.executable, self.shellens_path, 'does_not_exist.sh'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: File does_not_exist.sh not found", result.stdout)
        self.assertNotIn("Perfect! No formatting, style, or dead code issues found", result.stdout)

    def test_mixed_valid_and_missing_files(self):
        # Verify behavior with mixed valid and missing files
        valid_file = os.path.join(os.getcwd(), 'dummy_valid.sh')
        with open(valid_file, 'w') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nprintf 1\n")

        result = subprocess.run([sys.executable, self.shellens_path, valid_file, 'does_not_exist.sh'], capture_output=True, text=True)
        os.remove(valid_file)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: File does_not_exist.sh not found", result.stdout)
        self.assertNotIn("Perfect! No formatting, style, or dead code issues found in", result.stdout)

    def test_directory_passed_as_script(self):
        # Verify behavior when directory is passed as script
        test_dir = os.path.join(os.getcwd(), 'dummy_dir')
        if not os.path.exists(test_dir):
            os.mkdir(test_dir)

        result = subprocess.run([sys.executable, self.shellens_path, test_dir], capture_output=True, text=True)
        os.rmdir(test_dir)

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"Error: Path {test_dir} is not a regular file", result.stdout)

    def test_unreadable_file(self):
        # Verify behavior with unreadable file
        unreadable_file = os.path.join(os.getcwd(), 'unreadable.sh')
        with open(unreadable_file, 'w') as f:
            f.write("#!/bin/bash\necho 1\n")
        os.chmod(unreadable_file, 0o000)

        result = subprocess.run([sys.executable, self.shellens_path, unreadable_file], capture_output=True, text=True)
        os.chmod(unreadable_file, 0o644)
        os.remove(unreadable_file)

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"Error: File {unreadable_file} is not readable", result.stdout)

    def test_binary_file_handling(self):
        # Verify behavior with binary file
        binary_file = os.path.join(os.getcwd(), 'dummy.bin')
        with open(binary_file, 'wb') as f:
            f.write(b'\x80\x81\x82\x83')

        result = subprocess.run([sys.executable, self.shellens_path, binary_file], capture_output=True, text=True)
        os.remove(binary_file)

        self.assertEqual(result.returncode, 1)
        self.assertIn("not valid UTF-8", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_double_dash_terminator(self):
        # Verify double dash terminator handling
        weird_file = os.path.join(os.getcwd(), '-weird_name.sh')
        with open(weird_file, 'w') as f:
            f.write("#!/bin/bash\necho 1\n")

        result = subprocess.run([sys.executable, self.shellens_path, '--', weird_file], capture_output=True, text=True)
        os.remove(weird_file)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Use 'printf' instead of 'echo'", result.stdout)
        self.assertNotIn("Unknown option", result.stdout)

    def test_duplicate_flags(self):
        # Verify behavior with duplicate flags
        test_file = os.path.join(os.getcwd(), 'dummy_cli_test.sh')
        with open(test_file, 'w') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nprintf 1\n")
        result = subprocess.run([sys.executable, self.shellens_path, '--verbose', '--verbose', test_file], capture_output=True, text=True)
        os.remove(test_file)
        self.assertEqual(result.returncode, 0)

    def test_stdin_redirects_with_empty_args(self):
        # Verify stdin redirects with empty arguments
        result = subprocess.run([sys.executable, self.shellens_path], input="printf 1\n", capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage: shellens", result.stdout)

    def test_wildcard_globbing(self):
        # Verify wildcard globbing support
        file1 = os.path.join(os.getcwd(), 'test_glob_1.sh')
        file2 = os.path.join(os.getcwd(), 'test_glob_2.sh')
        with open(file1, 'w') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nprintf 1\n")
        with open(file2, 'w') as f:
            f.write("#!/bin/bash\nset -eu\nset -o pipefail\nprintf 2\n")

        glob_pattern = os.path.join(os.getcwd(), 'test_glob_*.sh')
        result = subprocess.run([sys.executable, self.shellens_path, glob_pattern], capture_output=True, text=True)

        os.remove(file1)
        os.remove(file2)

        self.assertEqual(result.returncode, 0)
        self.assertIn("Perfect! No formatting, style, or dead code issues found in", result.stdout)
        self.assertIn("test_glob_1.sh", result.stdout)
        self.assertIn("test_glob_2.sh", result.stdout)

    def test_stdin_linting(self):
        # Verify stdin linting
        code = "#!/bin/bash\necho 1\n"
        result = subprocess.run([sys.executable, self.shellens_path, '-'], input=code, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Use 'printf' instead of 'echo'", result.stdout)
        self.assertIn("<stdin>", result.stdout)

    def test_no_color_flag(self):
        # Verify no-color flag disables ANSI colors
        test_file = os.path.join(os.getcwd(), 'dummy_color.sh')
        with open(test_file, 'w') as f:
            f.write("#!/bin/bash\necho 1\n")

        result = subprocess.run([sys.executable, self.shellens_path, '--no-color', test_file], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('\033[', result.stdout)

        env = os.environ.copy()
        env['NO_COLOR'] = '1'
        result_env = subprocess.run([sys.executable, self.shellens_path, test_file], env=env, capture_output=True, text=True)
        self.assertNotIn('\033[', result_env.stdout)

        os.remove(test_file)

if __name__ == '__main__':
    unittest.main()
