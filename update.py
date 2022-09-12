import asyncio
from dataclasses import dataclass
import re
import shutil
from typing import Tuple
import zipfile
from pathlib import Path

import httpx
from aioconsole import ainput, aprint


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
        choice = (await ainput(question + prompt)).lower()
        if default is not None and choice == "":
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' " "(or 'y' or 'n').")


async def confirm_next():
    await ainput("Press Enter to continue...")


async def download_build(fn, url):
    # urllib.request.urlretrieve(url, fn)
    client = httpx.AsyncClient(follow_redirects=True)
    async with client.stream("GET", url) as r:
        with open(fn, "wb") as f:
            async for chunk in r.aiter_bytes():
                await asyncio.to_thread(f.write, chunk)


async def pick_device_serial():
    print()
    print("Querying devices with ADB ...")
    while True:
        stdout, _ = await check_call(["adb", "devices"], capture_stdout=True)

        # wait at least 3 seconds between ADB calls
        delay = asyncio.create_task(asyncio.sleep(3))

        for line in stdout.splitlines():
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
        await ainput("Press Enter to try again ...")


def extract_bootimg(fn):
    print("Extracting boot.img ... ", end="", flush=True)
    with zipfile.ZipFile(fn) as z:
        with z.open("boot.img") as zf, open("boot.img", "wb") as f:
            shutil.copyfileobj(zf, f)
    print("done.")


async def patch_bootimg(serial):
    adb = ["adb", "-s", serial]
    await check_call(adb + ["push", "boot.img", "/sdcard/Download/boot.img"])
    # Magisk app "Patch file method" seems to have KEEPFORCEENCRYPT=true and KEEPVERITY=true
    # when setting these two, the patched boot image is identical to the one created by the app
    await check_call(
        adb
        + [
            "shell",
            "KEEPFORCEENCRYPT=true",
            # "PATCHVBMETAFLAG=true",
            "KEEPVERITY=true",
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


async def adb_reboot_sideload(serial):
    adb = ["adb", "-s", serial]

    print("Rebooting to adb sideload mode.")
    await check_call(adb + ["reboot", "sideload"])

    while True:
        # wait at least 3 seconds between ADB calls
        await asyncio.create_task(asyncio.sleep(3))

        print("Waiting for device to enter adb sideload mode ...")
        stdout, _ = await check_call(["adb", "devices"], capture_stdout=True)

        for line in stdout.splitlines():
            line = line.strip()
            if re.match(f"{serial}\tsideload", line):
                return


async def adb_install_update(serial, fn):
    adb = ["adb", "-s", serial]
    await check_call(adb + ["sideload", fn])


async def adb_reboot_bootloader(serial):
    adb = ["adb", "-s", serial]

    print("Rebooting to fastboot mode.")
    await check_call(adb + ["reboot", "bootloader"])


async def wait_for_fastboot(serial):
    while True:
        print("Waiting for device to enter fastboot mode ...")
        stdout, _ = await check_call(["fastboot", "devices"], capture_stdout=True)

        for line in stdout.splitlines():
            line = line.strip()
            if re.match(f"{serial}\tfastboot", line):
                return

        # wait at least 3 seconds between ADB calls
        await asyncio.create_task(asyncio.sleep(3))


async def fb_install_bootimg(serial):
    await check_call(["fastboot", "-s", serial, "flash", "boot", "patched-boot.img"])


async def fb_reboot_system(serial):
    await check_call(["fastboot", "-s", serial, "reboot"])


async def main():
    url = "https://mirrorbits.lineageos.org/full/beryllium/20220910/lineage-19.1-20220910-nightly-beryllium-signed.zip"
    fn = Path("lineage-19.1-20220910-nightly-beryllium-signed.zip")
    # url = "https://mirrorbits.lineageos.org/full/beryllium/20220903/lineage-19.1-20220903-nightly-beryllium-signed.zip"
    # fn = Path("lineage-19.1-20220903-nightly-beryllium-signed.zip")
    # url = "https://mirrorbits.lineageos.org/recovery/beryllium/20220910/lineage-19.1-20220910-recovery-beryllium.img"
    # fn = "lineage-19.1-20220910-recovery-beryllium.img"

    if fn.is_file():
        print("File exists, skipping download.")
        dl_task = None
    else:
        print("Starting OTA zip download in the background.")
        dl_task = asyncio.create_task(download_build(fn, url))

    serial = await pick_device_serial()
    await adb_root(serial)

    if dl_task is not None:
        print("Waiting for download ... ", end="", flush=True)
        await dl_task
        print("finished.")
        await asyncio.sleep(1)

    print("Extracting and patching boot image ...")
    extract_bootimg(fn)
    await patch_bootimg(serial)

    print(
        "Received Magisk-patched boot image from phone.",
        "Next step is rebooting to recovery in adb sideload mode and install the OTA zip.",
    )
    await ainput("Press Enter to continue")

    await adb_reboot_sideload(serial)
    print("Installing OTA zip:", fn)
    await adb_install_update(serial, fn)
    await asyncio.sleep(3)
    print(
        "ADB sideload command has finished. Please enter fastboot mode now, or reboot to bootloader."
    )

    await wait_for_fastboot(serial)
    print("Flashing Magisk-patched boot image: patched-boot.img")
    await fb_install_bootimg(serial)
    print("Finished flashing boot image.")

    await ainput("Press Enter to reboot to android.")
    await asyncio.sleep(2)
    await fb_reboot_system(serial)


if __name__ == "__main__":
    asyncio.run(main())
