import asyncio
from dataclasses import dataclass
import re
import shutil
import subprocess
import sys
from typing import Tuple
import zipfile
from pathlib import Path

import httpx
import aioconsole


@dataclass(frozen=True)
class ProcessError(Exception):
    message: str
    returncode: int
    stdout: bytes
    stderr: bytes


# taken from https://code.activestate.com/recipes/577058/
# licensed under MIT License
async def query_yes_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes": "yes", "y": "yes", "ye": "yes", "no": "no", "n": "no"}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        choice = (await aioconsole.ainput(question + prompt)).lower()
        if default is not None and choice == "":
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' " "(or 'y' or 'n').")


async def confirm_next():
    await aioconsole.ainput("Press Enter to continue...")


async def download_build(fn, url):
    # # urllib.request.urlretrieve(url, fn)
    # client = httpx.AsyncClient(follow_redirects=True)
    # async with client.stream("GET", url) as r:
    #     with open(fn, "wb") as f:
    #         async for chunk in r.aiter_bytes():
    #             f.write(chunk)
    await asyncio.sleep(1)


async def pick_device_serial():
    print()
    print("Querying devices with ADB ...")
    while True:
        proc: asyncio.subprocess.Process = await asyncio.create_subprocess_exec(
            *["adb", "devices"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            print(stderr)
            raise RuntimeError(
                "ADB terminated with non-zero exit code. stderr was printed."
            )

        # wait at least 3 seconds between ADB calls
        delay = asyncio.create_task(asyncio.sleep(3))

        for line in stdout.decode("utf-8").splitlines():
            line = line.strip()
            if m := re.match(r"([0-9a-f]+)\tdevice", line):
                print(f"ADB found device with serial {m.group(1)}")
                if await query_yes_no("Is that the correct device?") == "yes":
                    return m.group(1)
            elif m := re.match(r"([0-9a-f]+)\tunauthorized", line):
                print(
                    f"ADB found unauthorized device with serial {m.group(1)}. Make sure to confirm ADB authorization from this computer."
                )
        print(
            "No more devices found.",
            "Make sure your phone is connected and ADB turned on.",
        )
        print()
        print("Querying again ...")

        await delay


async def check_call(
    args: "list", capture_stdout=False, capture_stderr=False
) -> Tuple[str, str]:
    proc: asyncio.subprocess.Process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE if capture_stdout else None,
        stderr=asyncio.subprocess.PIPE if capture_stderr else None,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        # print(stderr, file=sys.stderr)
        raise ProcessError(
            "Subprocess failed with non-zero exit code.",
            returncode=proc.returncode,
            stderr=stderr,
            stdout=stdout,
        )
    if stdout is not None:
        stdout = stdout.decode("utf-8")
    if stderr is not None:
        stderr = stderr.decode("utf-8")
    return stdout, stderr


async def adb_root(serial: str):
    while True:
        try:
            _, _ = await check_call(["adb", "-s", serial, "root"])
            stdout, _ = await check_call(
                ["adb", "-s", serial, "shell", "whoami"], capture_stdout=True
            )
            if stdout.strip() == "root":
                return
        except ProcessError:
            print("ADB command failed while checking for root permissions.")

        print(
            "Could not acquire root access.",
            "Make sure you've enabled ADB root mode in Developer Settings.",
        )
        await aioconsole.ainput("Press Enter to try again ...")


def extract_bootimg(fn):
    print("Extracting boot.img ... ", end="", flush=True)
    with zipfile.ZipFile(fn) as z:
        with z.open("boot.img") as zf, open("boot.img", "wb") as f:
            shutil.copyfileobj(zf, f)
    print("done.")


async def patch_bootimg(serial):
    adb = ["adb", "-s", serial]
    await check_call(adb + ["push", "boot.img", "/sdcard/Download/boot.img"])
    # TODO: this seems to produce an image not identical to the Magisk app patcher. find out what's different about it.
    await check_call(
        adb
        + [
            "shell",
            "KEEPFORCEENCRYPT=true",
            "/data/adb/magisk/boot_patch.sh",
            "/sdcard/Download/boot.img",
        ]
    )
    await check_call(
        adb
        + [
            "shell",
            "mv",
            "/data/adb/magisk/new-boot.img",
            "/sdcard/Download/patched-boot.img",
        ]
    )
    await check_call(adb + ["pull", "/sdcard/Download/patched-boot.img"])


async def main():
    url = "https://mirrorbits.lineageos.org/full/beryllium/20220910/lineage-19.1-20220910-nightly-beryllium-signed.zip"
    fn = Path("lineage-19.1-20220910-nightly-beryllium-signed.zip")
    # url = "https://mirrorbits.lineageos.org/recovery/beryllium/20220910/lineage-19.1-20220910-recovery-beryllium.img"
    # fn = "lineage-19.1-20220910-recovery-beryllium.img"

    if fn.is_file():
        print("File exists, skipping download.")
        dl_task = None
    else:
        print("Starting OTA zip download in the background.")
        dl_task = asyncio.create_task(download_build())

    serial = await pick_device_serial()
    await adb_root(serial)

    extract_bootimg(fn)
    await patch_bootimg(serial)

    if dl_task is not None:
        print("Waiting for download ... ", end="", flush=True)
        await dl_task
        print("finished.")


if __name__ == "__main__":
    asyncio.run(main())
