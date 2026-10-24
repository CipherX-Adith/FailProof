import subprocess


def run_untrusted_command(command):
    return subprocess.run(command, shell=True, check=False)
