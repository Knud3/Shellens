# Shellens: A Better Linter for Bash and Shell

## Why Shellens? (...if you already use ShellCheck and shfmt)

Because standard tools only check *syntax*. Shellens enforces **architecture**.

Shellens is a high-level static analysis engine designed to stop script rot. **It natively wraps `shfmt` and `shellcheck`** to handle standard formatting and security basics, and then layers on a powerful, custom-built Python state machine to enforce enterprise-grade defensive programming.

Bash scripts usually start as simple 10-line automations but inevitably mutate into fragile, unmaintainable over 1000 line monoliths. While tools like ShellCheck are incredible for catching syntax errors, they won't tell you that your function has a cyclomatic complexity of 45, or that you have phantom global variables leaking across five different files, or that you forgot to declare a variable as `local` inside a math block.

It goes beyond standard syntax checking to enforce a rigorous architectural philosophy, focusing on strict POSIX compliance, predictable formatting, and visual hierarchy. It acts as the ultimate architectural guardrail for both your CI/CD pipelines and AI coding assistants, ensuring your scripts remain reliable, modular, free of dead code, and unbreakable as they scale.

## Features at a Glance

- **Hybrid Analysis Engine:** Uses a robust stack-based state machine (`quote_stack`) and structural parsing to perfectly track nested subshells, single/double/ANSI C quotes (`$'...'`), and heredocs where standard Python AST parsers fail.
- **External Tool Orchestration:** Seamlessly wraps `shfmt` (for indentation) and `ShellCheck` (for security), intelligently deduplicating their output to prevent warning spam and filter out noise. Automatically enables all optional ShellCheck rules (`-o all`) unless a `.shellcheckrc` configuration file is found (resolving via script directories, working directory, or home directory), perfectly respecting enterprise configurations.
- **Dead Code & Variable Scope Tracking:** Cross-references function calls and global variable expansions across multiple files to find phantom code.
- **Cyclomatic Complexity:** Mathematically scores functions based on branching logic to prevent unreadable monoliths.
- **CI/CD Ready:** Exits with `1` if any violations are found, instantly failing the pipeline. Shellens operates with a strict "Fail-Fast" validation pass: if any provided file is missing, unreadable, or a directory, or if an unknown CLI flag is provided, it instantly aborts with an error `1` without performing partial linting. Supports beautiful colorized CLI output.
- **AI/LLM Verification Loop:** Outputs clear, human-readable language detailing exact infractions, making it an ideal guardrail for AI coding assistants. When used in an automated loop, it forces the AI to iterate and verify that every generated line strictly adheres to architectural rules before code is finalized.
- **Comprehensive Test Suite:** Backed by an extensive, fully sanitized Python `unittest` suite (`test_shellens`) covering over 90 complex edge cases to ensure zero regressions.

## Tooling & Dependencies

- **Python 3** (Core engine)
- **[shfmt](https://github.com/mvdan/sh)** (Used for base 2-space structural indentation checking)
- **[ShellCheck](https://www.shellcheck.net/)** (Used for deep vulnerability and syntax scanning)

*Note: If `shfmt` and/or `shellcheck` are missing from the system, Shellens will intentionally crash and exit with code `1`. This ensures CI/CD pipelines never silently pass due to a missing dependency.*

## Installation (System-Wide)

You can keep the `.py` extension on the source file for IDE syntax highlighting, but still run it natively as `shellens` using a symbolic link.

```bash
# 1. Make the script executable
chmod +x /path/to/shellens.py

# 2. Create an extensionless symlink in your local bin (or /usr/local/bin)
ln -s /path/to/shellens.py ~/.local/bin/shellens

# 3. Ensure ~/.local/bin is in your $PATH
```

## Usage

Run Shellens against one or multiple shell scripts:

```bash
shellens /path/to/script.sh
shellens main.sh utils.sh config.sh
shellens *.sh
```

### Linting via Standard Input (stdin)

Shellens can natively parse and lint code directly from a pipeline or a redirection by passing the `-` symbol as a file path.

```bash
cat script.sh | shellens -
shellens - < script.sh
shellens - <<< '#!/bin/bash\necho "Hello"'
```

## Development & Testing

To verify functionality before deployment or after making custom modifications, run the included `unittest` suite. The test suite automatically cleans up its own generated dummy files and leaves zero artifacts.

```bash
python3 -m unittest test_shellens.py
```

### Known Limitations & Contributor Roadmap

While Shellens is robust, parsing Bash via Regex/State Machines instead of a compiled AST carries inherent boundaries. The following edge cases are documented via failing tests in the test suite and serve as a roadmap for future architectural upgrades:

- **Complex Associative Arrays:** Highly complex associative array declarations using nested brackets (e.g. `declare -A arr=( [${keys[0]}]=1 )`) or multi-line spaces may bypass standard scoping and spacing rules.
  - *The Challenge:* Regex cannot cleanly parse deeply nested, multi-line parenthesis `()` and bracket `[]` structures.
  - *The Fix:* Requires implementing a structural "bracket balancing" stack (similar to the existing `quote_stack`).
- **Global `declare`/`typeset`:** Variables declared globally using `declare var=1` or `typeset var=1` instead of `export`, `readonly`, or standard assignments (`var=1`) will currently bypass the global Multi-File Dead Code analysis engine.
  - *The Challenge:* `declare` behaves dynamically (local inside functions, global outside) and accepts massive flag variations (`-a`, `-A`, `-g`, `-i`, `-r`, `-x`).
  - *The Fix:* Updating the regex to safely capture all possible flag combinations `(?:-[a-zA-Z]+\s+)*` while ensuring local function variables are not accidentally pulled into the global namespace.
- **Quoted Heredoc Expansions:** Shellens currently evaluates variable expansions globally across the file. It will flag a variable as "Used" if it appears inside a quoted heredoc (e.g. `cat << 'EOF'\n ${var}\n EOF`), even though Bash treats this as literal text.
  - *The Challenge:* The Dead Code analyzer is extremely fast because it runs a global `re.findall` sweep.
  - *The Fix:* Requires replacing the global regex with a line-by-line, state-aware tokenizer that tracks heredoc initialization quotes and selectively pauses the variable scanner.
- **Rule Configuration `.shellensrc`:** Separate critical security/scoping rules from subjective formatting preferences, allowing developers to customize or toggle specific style rules.

## Philosophy & Customization

Shellens is built to enforce universal **industry best practices** for defensive programming, security, and POSIX compatibility. To achieve complete architectural consistency, it also ships with curated formatting defaults out-of-the-box.

Currently, these structural rules are enforced globally to guarantee a unified codebase standard. A major goal for the next release is the introduction of a `.shellensrc` configuration file, which will allow teams to fine-tune these style preferences to better fit their internal workflows.

## Flags & Options

- `--markdown`: Generates a Markdown table report (ideal for GitLab/GitHub CI artifacts). ShellCheck warnings are automatically converted to clickable links. This will generate a file named `<script_name>-report.md` (e.g., `main-sh-report.md`) in the current directory. *(Note: When this flag is used, the process will intentionally exit with `0` even if issues are found, to ensure the CI pipeline proceeds to the next step and publishes the report artifact).*
- `--verbose`: Displays minor informational notices (like `COMPLEXITY` refactoring suggestions and `UPPERCASE` variable advice) that are otherwise hidden to reduce terminal noise.
- `--sh`: Forces Shellens to operate in POSIX `sh` compatibility mode. By default, the Python engine will also automatically detect POSIX mode if the script's shebang is `#!/bin/sh` or references `ash`/`dash`. In POSIX mode, aggressive Bash-only enforcement rules (like banning `[ ... ]` tests) are gracefully disabled to support environments like Alpine Linux.
- `--no-color`: Strips all ANSI color escape codes from the terminal output. *(Note: Shellens automatically strips colors if it detects `sys.stdout` is not an interactive TTY, or if the `NO_COLOR` environment variable is set).*

## Core Philosophies & Rulesets

### Defensive Programming, Portability & Strict Mode

- **Global Strict Mode:** Shellens strictly enforces the presence of `set -o errexit`, `set -o nounset`, and `set -o pipefail` (or their short forms `-e`, `-u`).
- **Nounset Safety (`-u`):** Using `set -u` is dangerous if you check the existence of unbound variables. Shellens flags naked variable checks in conditionals (e.g., `[[ -z "${foo}" ]]`) and forces you to use a safe fallback: `[[ -z "${foo-}" ]]`.
- **Suspended Strict Mode Tracking:** Intelligently tracks when `set -e` is temporarily suspended (e.g., inside `if` conditions or `|| true` blocks) and warns if critical functions are invoked without error-handling safety nets `[SC2310]`.
- **Swallowed Exit Codes:** Flags subshells passed directly as arguments to functions, warning that internal command failures will be silently masked `[SC2312]`.
- **Naked Readonly:** Flags `readonly foo` if `foo` is never assigned a value anywhere in the script (including via `read` or `for` loops) and is not explicitly guarded by an expansion check (like `${foo:?}`). This prevents `nounset` crashes.
- **Bash 3.2 / macOS Compatibility:** Actively flags Bash 4.0+ features (`declare -g`, `declare -A`, `mapfile`, `readarray`) and fundamentally incompatible cross-platform commands (like GNU `sed -i`) to ensure strict portability.
- **Dangerous Patterns:** Actively flags severe security and stability risks like `eval`, piped curl-to-shell (`curl | bash`), `chmod 777`, `kill -9`, and leftover debug traces (`set -x` / `xtrace`) that can leak CI/CD secrets. *(Note: Conditional `set -x` inside `if` statements is intelligently allowed for safe debugging).*
- **Magic Number Detection:** Scans for raw numeric literals (like `sleep 10` or `-eq 50`) embedded deep in logic and suggests extracting them into named constants for better maintainability.

### Styling & Formatting

Shellens enforces strict **2-space indentation**, delegating the heavy lifting to `shfmt`. However, it implements custom "Intelligent Exception Handlers" to override `shfmt`'s limitations:

- **Intelligent Deduplication:** If the Python engine detects a highly specific formatting error (e.g., *Inconsistent indentation jump* or *Misaligned closing brace*), it will actively suppress `shfmt`'s redundant *Structural mismatch* error for that line.
- **Cascading Case Statements:** Allows `case` patterns to be indented 2 spaces inward, and the code inside them 4 spaces inward (which `shfmt` normally rejects).
- **Line Endings:** Files must use Unix `LF` line endings. `CRLF` is instantly rejected.
- **Trailing Whitespace:** Flagged universally, including after line-continuation backslashes `\`.
- **Semantic Line Length:** Enforces an 80-character maximum line length.
  - *Exceptions:* Comments, URLs (`http://`), `echo`, `printf`, custom `log` commands, and AppleScript (`osascript`) blocks are allowed to exceed this limit to preserve readability.
- **Operator Wrapping:** Enforces that line-wrapped operators (`|`, `&&`, `||`) must appear at the *beginning* of the next line, rather than dangling at the end of the current line.

### Shell Keyword & Purity

- **Ban `echo`:** As it behaves inconsistently across OS environments (e.g., macOS vs GNU). Shellens bans `echo` and enforces the use of `printf`.
- **Clean Terminal Output:** Enforces that terminal output strings (via `printf` or custom loggers) do not end with a trailing period. Ellipses (`...`) are explicitly allowed for loading states.
- **Consecutive `printf` Merging:** Flags back-to-back `printf` statements and suggests combining them into a single, multi-line `printf` to reduce subshell/I/O overhead.
- **Modern Command Substitution:** Enforces the use of `$(...)` over legacy backticks `` `...` `` for nested command substitution `[SC2006]`.
- **Useless Use of Cat:** Identifies inefficient `cat file | cmd` piping and suggests direct file redirection `cmd < file` `[SC2002]`.
- **Ban POSIX `[ ... ]` Tests:** The traditional syntax is fragile and subject to word splitting. Shellens bans `[ ... ]` and enforces the modern Bash keyword `[[ ... ]]`. Automatically suppresses redundant ShellCheck `[SC2292]` warnings.
- **Strict String Equality:** Enforces the use of the idiomatic `==` operator for string comparison inside Bash `[[ ... ]]` blocks, rather than the POSIX `=` operator.
- **Ban Non-POSIX Functions:** Rejects the `function foo()` syntax. Forces `foo() {`.
- **Strict Redirection:** Bans lazy bashisms like `&>` and `>&`. Enforces `> file 2>&1`. Furthermore, enforces exact spacing around null routing (` > /dev/null `), while intelligently ignoring file descriptor routing (`2> /dev/null`).
- **No Trailing Semicolons:** Bans unnecessary semicolons at the end of lines.

### Variable Conventions & Scoping

- **Curly Brace Enforcement:** Flags bare variables (`$var`) and demands explicit boundaries (`${var}`).
  - *Exceptions:* Standard bash globals (`$1`, `$?`, `$$`, etc.) and array indices (`arr[$var]`).
- **Quote Safe Variables:** Enforces that all variables susceptible to word-splitting and globbing are safely wrapped in double quotes `[SC2086]`.
- **Unassigned Variable Tracking:** Analyzes execution flow to flag variables that are referenced before they are assigned `[SC2154]`.
- **Strict Local Scoping:** If a variable is assigned inside a function, it *must* be declared as `local` or `readonly`. The engine uses a forward-looking scanner to understand multi-line declarations (e.g., `local a b \ c`).
  - *Exceptions:* Known standard environmental variables (`PATH`, `TZ`, `IFS`).
- **Uppercase Naming:** Flags `UPPERCASE` variables to confirm they are intended to be user-configurable constants (Only shown in `--verbose` mode).
- **Alphabetical Sorting:** Contiguous blocks of variable assignments (and inline lists like `readonly A B C`) must be sorted alphabetically.
  - *Exception:* If a variable assignment dynamically references a variable declared earlier in the same block, execution order takes priority and alphabetical sorting is bypassed.
- **Contiguous Assignment Blocks:** Prevents inserting empty lines inside a block of variable assignments, enforcing grouped assignment lists to maintain visual density and block-level sorting logic.

### Architectural Complexity

- **Cyclomatic Complexity:** Counts branching logic (`if`, `elif`, `for`, `while`, `&&`, `||`, `case`) inside functions. If the score exceeds 15, it throws a `[COMPLEXITY]` warning.
- **Monolith Detection:** Flags functions that contain more than 50 lines of executable code.
  - *Exception:* The `main()` orchestrator function is exempt from both complexity and length checks. (Only shown in `--verbose` mode).

### Visual Spacing & Parentheses

- Enforces breathing room around subshells, arrays, and math context.
  - **Arrays:** `=( ... )`
  - **Subshells:** `$( ... )`
  - **Math:** `$(( ... ))` and `(( ... ))`
- **Math Context Variable Expansion:** Inside `(( ... ))`, using `${var}` forces string expansion before math evaluation, risking a crash if the variable is empty. It enforces dropping the `$` (e.g., `(( c == var ))`).
- **Arithmetic Increments:** Suggests replacing string-based math assignments (e.g., `var=$(( var + 1 ))`) with the cleaner, idiomatic Bash arithmetic evaluation `(( var++ ))`.
- **Test Command Syntax:** Identifies malformed condition logic inside test brackets, such as using `=` instead of `==` or confusing string/integer comparison operators `[SC2078]`.

### The Hybrid `then` Placement Rule

This rule balances vertical density for simple commands with rigid visual hierarchy for complex architecture:

- **Simple Single-Line `if`:** The `; then` **must** be on the same line to save screen space.
- **Complex Multi-Line `if`:** If the condition spans multiple lines (using `\` or `&&`/`||`), the `then` keyword **must** be placed on its own dedicated line, aligned with the `if`. It cannot share a line with other code.

### Linguistic Comment Formatting

Comments are treated differently depending on where they live in the script. The engine uses a state tracker (`has_seen_code`) to differentiate between the "Front Matter" (top-level documentation) and inline imperative comments.

Once the first line of executable code is seen, the following strict rules apply to all subsequent comments:

- **Imperative Mood:** Comments must act as commands. Shellens bans grammatical articles (`a`, `an`, `the`). (e.g., `# Download file` instead of `# Download the file`).
- **No Trailing Periods:** Imperative commands do not end in punctuation.
- **Exactly One Empty Line:** Every standalone code comment block must be preceded by exactly one empty line to ensure visual separation from the previous code block. Inline comments (`code # comment`) bypass this rule.
- **No Contiguous Blocks:** Prevents stacking multiple comment blocks separated by empty lines with no actual code in between.
- **Header Blocks:** Dividers starting with `#####` must be exactly 80 characters long. They may be preceded by 1 or 2 empty lines.
- **Comment Indentation:** Enforces that inline comments strictly align with the indentation of the code block immediately following them. Intelligently supports closing/branching wrappers (`fi`, `done`, `esac`, `}`, `elif`, `else`) by allowing comments to align with either the inner nested code or the outer wrapper.
- **Exceptions:**
  - ShellCheck compiler directives (`# shellcheck disable=...`) bypass all spacing and grammar rules.
  - Comments containing URLs (`http://`) bypass grammar and trailing period rules.

### Embedded Language Safety

- **AWK Injection:** Scans for double-quoted `awk "..."` scripts that contain Bash variables (`$var`). This is an injection risk as variables expand before awk parses them. Forces the use of `awk '...'` and passing variables safely via the `-v` flag.
- **Blind Formatting:** When `shfmt` encounters multi-line strings or embedded `awk` scripts, it goes blind. The Python engine takes over, applying custom heuristics to ensure proper indentation and aligned closing braces `}` inside those blocks.

### Multi-File Dead Code Analysis

When run against multiple scripts, Shellens performs a global two-pass cross-reference:

1. Builds a master list of all globally assigned variables and declared functions.
2. Scans all files for usages (`$var`, `${var}`, `${#var[@]}`, `${!var[@]}`, or function calls).
3. Flags any function or global variable that is defined but never invoked across the entire codebase.
