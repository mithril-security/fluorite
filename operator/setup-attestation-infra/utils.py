import subprocess
import textwrap
import shlex


def run_command(args):
    try:
        return subprocess.run(args, text=True, capture_output=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        command = " ".join(args)
        indented_stderr = textwrap.indent(e.stderr, prefix="   ")
        indented_stdout = textwrap.indent(e.stdout, prefix="   ")
        error_message = (
            f"Command '{command}' failed.\n"
            f"Stdout:\n{indented_stdout}"
            f"Stderr:\n{indented_stderr}"
        )

        raise RuntimeError(error_message) from e
