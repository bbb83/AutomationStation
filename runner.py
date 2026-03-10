import subprocess

def run_nmap_xml(args: list[str]) -> str:
    proc = subprocess.run(
        ["nmap", *args, "-oX", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        raise RuntimeError(err if err else "nmap failed")

    return proc.stdout