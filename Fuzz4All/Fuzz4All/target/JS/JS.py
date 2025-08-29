import os
import subprocess
from typing import List, Union

from Fuzz4All.target.target import FResult, Target
from Fuzz4All.util.util import comment_remover

class JSTarget(Target):
    """
    Minimal JavaScript target using Node.js:
    - Prompts LLM to generate JS snippets that call a chosen target API.
    - Writes code to /tmp and validates by running `node`.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs["template"] == "fuzzing_with_config_file":
            config_dict = kwargs["config_dict"]
            self.prompt_used = self._create_prompt_from_config(config_dict)
            self.config_dict = config_dict
        else:
            raise NotImplementedError("Only config-file template is supported for JS")

        # Let the generator stop early if it starts a new module header, etc.
        self.special_eos = None  # keep None unless you want something like `"use strict"`

    # ---- Prompting helpers -------------------------------------------------

    def wrap_prompt(self, prompt: str) -> str:
        # match GO/JAVA style: comment -> separator -> begin
        return f"// {prompt}\n{self.prompt_used['separator']}\n{self.prompt_used['begin']}"

    def wrap_in_comment(self, prompt: str) -> str:
        return f"// {prompt}"

    def filter(self, code: str) -> bool:
        # Ensure the generated code actually targets the requested API symbol
        code = code.replace(self.prompt_used["begin"], "").strip()
        code = comment_remover(code)
        return self.prompt_used["target_api"] in code

    def clean(self, code: str) -> str:
        return comment_remover(code)

    def clean_code(self, code: str) -> str:
        # remove the “begin marker” line and blank lines, strip comments
        code = code.replace(self.prompt_used["begin"], "").strip()
        code = comment_remover(code)
        code = "\n".join([ln for ln in code.split("\n") if ln.strip() != ""])
        return code

    # ---- Files & validation ------------------------------------------------

    def write_back_file(self, code: str) -> str:
        code = self.clean_code(code)
        wb = f"/tmp/temp{self.CURRENT_TIME}.js"
        with open(wb, "w", encoding="utf-8") as f:
            f.write(code)
        return wb

    def validate_individual(self, filename: str) -> (FResult, str):
        """
        Runs `node` to validate. If you only want a syntax check without executing,
        you can switch to `node --check <file>` below.
        """
        try:
            # quick syntax check variant (uncomment if you prefer):
            # exit_code = subprocess.run(
            #     ["node", "--check", filename],
            #     capture_output=True, text=True, timeout=self.timeout
            # )
            exit_code = subprocess.run(
                ["node", filename],
                capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            return FResult.TIMED_OUT, "javascript"
        except FileNotFoundError:
            # Node.js not installed / not in PATH
            return FResult.ERROR, "node-not-found"

        if exit_code.returncode == 0:
            return FResult.SAFE, exit_code.stdout or "ok"
        else:
            # Nonzero return means runtime error or console.assert failure etc.
            # Treat as FAILURE so the fuzzer learns from it.
            stderr = exit_code.stderr or exit_code.stdout
            return FResult.FAILURE, stderr

    # ---- Config-driven prompt scaffold ------------------------------------

    def _create_prompt_from_config(self, cdict):
        """
        Mirrors other targets: build the docstring + examples + trigger token.
        Expected YAML fields under `target:`:
          - language: "javascript"
          - api_name: string you want to call in generated code (the 'target_api')
          - docstring: high-level text about the API
          - example_code: a small JS example showing intended usage
          - input_hint: a short marker that precedes model output, e.g. '// Write code below'
          - trigger_token: a separator, e.g. '/* === */'
        """
        target = cdict["target"]
        fuzzing = cdict["fuzzing"]

        api_name = target.get("api_name", "targetApi")
        docstring = target.get("docstring", f"Implement code that uses {api_name}.")
        example = target.get("example_code", f"function demo() {{ console.log({api_name}); }}")
        input_hint = target.get("input_hint", "// Write code below")
        trigger = target.get("trigger_token", "/* === */")

        # This is what Target.auto_prompt() expects
        return {
            "docstring": docstring,
            "example_code": example,
            "separator": trigger,
            "begin": input_hint,
            "hw_prompt": fuzzing.get("handwritten_prompt", ""),  # optional
            "target_api": api_name,
        }

