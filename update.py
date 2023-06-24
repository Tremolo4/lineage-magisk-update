from dataclasses import dataclass
import hashlib
import json
import re
import shutil
import subprocess
import threading
import time
import zipfile
from datetime import date
from pathlib import Path
import urllib.request
import urllib.parse

LINEAGEOS_DOWNLOADS = "https://download.lineageos.org"
DEVICE = "beryllium"
RECOVERY_URL_TEMPLATE = "https://mirrorbits.lineageos.org/recovery/{device}/{date}/lineage-{version}-{date}-recovery-{device}.img"


@dataclass(frozen=True)
class ProcessError(Exception):
    message: str
    returncode: int
    stdout: bytes
    stderr: bytes


# taken from https://code.activestate.com/recipes/577058/
# licensed under MIT License
def query_yes_no(question, default="yes"):
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
        choice = (input(question + prompt)).lower()
        if default is not None and choice == "":
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' " "(or 'y' or 'n').")


@dataclass
class BuildInfo:
    date: str
    fn: Path
    url: str
    sha256: str
    fn_r: Path
    url_r: str
    sha256_r: str


@dataclass
class DownloadResult:
    successful: bool = False
    successful_r: bool = False


def get_newest_build_info():
    with urllib.request.urlopen(
        f"{LINEAGEOS_DOWNLOADS}/api/v1/{DEVICE}/nightly/yaddayadda"
    ) as res:
        text = res.read()
    data = json.loads(text)
    newest = sorted(data["response"], key=lambda build: build["datetime"])[-1]

    info = BuildInfo(
        date=date.fromtimestamp(int(newest["datetime"])).strftime("%Y%m%d"),
        fn=newest["filename"],
        url=newest["url"],
        sha256=newest["id"],
        fn_r=None,
        url_r=None,
        sha256_r=None,
    )

    # sadly the api does not inform about recovery
    # get recovery info by assembling url with the same date as the ota, get hash with <url>?sha256
    info.url_r = RECOVERY_URL_TEMPLATE.format(
        device=DEVICE, date=info.date, version=newest["version"]
    )
    info.fn_r = Path(urllib.parse.unquote(urllib.parse.urlparse(info.url_r).path)).name
    with urllib.request.urlopen(info.url_r + "?sha256") as response:
        text = response.read().decode(response.headers.get_content_charset())
    info.sha256_r = text[:64]

    if info.fn != Path(info.fn).name or info.fn_r != Path(info.fn_r).name:
        raise RuntimeError(
            "LineageOS Download API returned filename containing a slash"
        )

    info.fn = Path(info.fn)
    info.fn_r = Path(info.fn_r)

    return info


def verify_sha256(path: Path, hash: str):
    BLOCK_SIZE = 8388608
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(BLOCK_SIZE):
            hasher.update(chunk)
    return hash == hasher.hexdigest()


def download_file(fn, url):
    urllib.request.urlretrieve(url, fn)
    # client = httpx.AsyncClient(follow_redirects=True)
    # async with client.stream("GET", url) as r:
    #     with open(fn, "wb") as f:
    #         async for chunk in r.aiter_bytes():
    #             await asyncio.to_thread(f.write, chunk)


def download_if_not_exists(fn: Path, url: str):
    if not fn.is_file():
        download_file(fn, url)


def do_downloads(
    info: BuildInfo,
    recovery_done: threading.Event,
    update_recovery: bool,
    result: DownloadResult,
):
    """Download recovery image, if update_recovery is True.
    When that's done (or immediately) set the recovery_done event.
    Then download the OTA zip."""

    skip_ota = info.fn.is_file()
    if update_recovery:
        download_if_not_exists(info.fn_r, info.url_r)
        result.successful_r = verify_sha256(info.fn_r, info.sha256_r)
        if not result.successful_r:
            recovery_done.set()
            # don't proceed with ota download
            return
    recovery_done.set()

    if not skip_ota:
        download_if_not_exists(info.fn, info.url)
    result.successful = verify_sha256(info.fn, info.sha256)


def pick_device_serial():
    print()
    print("Querying devices with ADB ...")
    while True:
        stdout, _ = check_call(["adb", "devices"], capture_stdout=True)

        # wait at least 3 seconds between ADB calls
        sleep_until = time.time() + 3.0

        for line in stdout.splitlines():
            line = line.strip()
            if m := re.match(r"([0-9a-f]+)\s+device", line):
                print(f"ADB found device with serial {m.group(1)}")
                if query_yes_no("Is that the correct device?") == "yes":
                    return m.group(1)
            elif m := re.match(r"([0-9a-f]+)\s+unauthorized", line):
                print(
                    f"ADB found unauthorized device with serial {m.group(1)}.",
                    "Make sure to confirm ADB authorization from this computer.",
                )
        print(
            "No more devices found.",
            "Make sure your phone is connected and ADB turned on.",
        )
        print()
        print("Querying again ...")

        time.sleep(max(sleep_until - time.time(), 0.0))


def check_call(args: "list", capture_stdout=False, capture_stderr=False):
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture_stdout else None,
        stderr=subprocess.PIPE if capture_stderr else None,
        check=True,
    )
    stdout, stderr = None, None
    if capture_stdout:
        stdout = proc.stdout.decode("utf-8")
    if capture_stderr:
        stderr = proc.stderr.decode("utf-8")
    return stdout, stderr


def adb_root(serial: str):
    print("Ensuring adb root access ... ")
    while True:
        try:
            _, _ = check_call(["adb", "-s", serial, "root"])
            stdout, _ = check_call(
                ["adb", "-s", serial, "shell", "whoami"], capture_stdout=True
            )
            if stdout.strip() == "root":
                print("Root access verified.")
                return
        except subprocess.CalledProcessError:
            print("ADB command failed while checking for root permissions.")

        print(
            "Could not acquire root access.",
            "Make sure you've enabled ADB root mode in Developer Settings.",
        )
        input("Press Enter to try again ...")


def extract_bootimg(fn):
    print("Extracting boot.img ... ", end="", flush=True)
    with zipfile.ZipFile(fn) as z:
        with z.open("boot.img") as zf, open("boot.img", "wb") as f:
            shutil.copyfileobj(zf, f)
    print("done.")


def patch_bootimg(serial):
    adb = ["adb", "-s", serial]
    check_call(adb + ["push", "boot.img", "/sdcard/Download/boot.img"])
    # Magisk app "Patch file method" seems to have KEEPFORCEENCRYPT=true and KEEPVERITY=true
    # when setting these two, the patched boot image is identical to the one created by the app
    check_call(
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
    check_call(
        adb
        + [
            "shell",
            "mv",
            "/data/adb/magisk/new-boot.img",
            "/sdcard/Download/patched-boot.img",
        ]
    )
    check_call(adb + ["pull", "/sdcard/Download/patched-boot.img"])


def adb_reboot_sideload(serial):
    adb = ["adb", "-s", serial]

    print("Rebooting to adb sideload mode.")
    check_call(adb + ["reboot", "sideload"])

    while True:
        # wait at least 3 seconds between ADB calls
        time.sleep(3)

        print("Waiting for device to enter adb sideload mode ...")
        stdout, _ = check_call(["adb", "devices"], capture_stdout=True)

        for line in stdout.splitlines():
            line = line.strip()
            if re.match(serial + r"\s+sideload", line):
                return


def adb_install_update(serial, fn):
    adb = ["adb", "-s", serial]
    check_call(adb + ["sideload", fn])


def adb_reboot_bootloader(serial):
    adb = ["adb", "-s", serial]

    print("Rebooting to fastboot mode.")
    check_call(adb + ["reboot", "bootloader"])


def wait_for_fastboot(serial):
    while True:
        print("Waiting for device to enter fastboot mode ...")
        stdout, _ = check_call(["fastboot", "devices"], capture_stdout=True)

        for line in stdout.splitlines():
            line = line.strip()
            if re.match(serial + r"\s+fastboot", line):
                return

        # wait at least 3 seconds between ADB calls
        time.sleep(3)


def fb_install_bootimg(serial):
    check_call(["fastboot", "-s", serial, "flash", "boot", "patched-boot.img"])


def fb_reboot_system(serial):
    check_call(["fastboot", "-s", serial, "reboot"])


def adb_update_recovery(serial, fn_r):
    adb = ["adb", "-s", serial]
    print("Transferring recovery image ...")
    check_call(adb + ["push", fn_r, f"/sdcard/Download/{fn_r}"])
    print("Flashing recovery image ...")
    check_call(
        adb
        + [
            "shell",
            "dd",
            f"if=/sdcard/Download/{fn_r}",
            "of=/dev/block/by-name/recovery",
        ]
    )
    print("Recovery update finished.")


def main():
    info = get_newest_build_info()

    print("Determined newest builds for OTA and recovery from LineageOS Download site:")
    print(info.fn)
    print(info.fn_r)

    if (
        query_yes_no("Do you want to install the latest LineageOS recovery as well?")
        == "yes"
    ):
        update_recovery = True
    else:
        update_recovery = False

    print(
        "Starting downloads in the background.",
        "Note that if a file already exists, the download will be silently skipped.",
    )
    recovery_done = threading.Event()
    dl_res = DownloadResult()
    dl_thread = threading.Thread(
        target=do_downloads,
        args=[info, recovery_done, update_recovery, dl_res],
        daemon=True,
    )
    dl_thread.start()

    serial = pick_device_serial()
    adb_root(serial)

    if update_recovery:
        print("Waiting for recovery download ... ", end="", flush=True)
        recovery_done.wait()
        print("finished.")
        if not dl_res.successful_r:
            print("SHA256 verification of recovery image failed!")
            print("Downloaded file is apparently corrupt. Aborting.")
            exit()
        else:
            print("SHA256 verified successfully.")
        input("Press Enter to continue with recovery flash")
        adb_update_recovery(serial, info.fn_r)
        time.sleep(1)

    print("Waiting for OTA download ... ", end="", flush=True)
    dl_thread.join()
    print("finished.")
    if not dl_res.successful:
        print("SHA256 verification of OTA zip failed!")
        print("Downloaded file is apparently corrupt. Aborting.")
        exit()
    else:
        print("SHA256 verified successfully.")

    msg = "Do you want to patch the boot image with Magisk and flash it?"
    magisk = query_yes_no(msg) == "yes"
    if magisk:
        print("Extracting and patching boot image ...")
        extract_bootimg(info.fn)
        patch_bootimg(serial)
        print("Received Magisk-patched boot image from phone.")

    input("Press Enter to reboot to adb sideload mode")
    adb_reboot_sideload(serial)
    msg = "Do you want to install the OTA (y) or skip this step (n)?"
    if query_yes_no(msg) == "yes":
        print("Installing OTA zip:", info.fn)
        adb_install_update(serial, info.fn)
        time.sleep(3)
        print("ADB sideload command has finished.")

    if magisk:
        print("Next step is installing the Magisk-patched boot image.")
        print("Please enter fastboot mode now, or reboot to bootloader.")
        wait_for_fastboot(serial)
        print("Flashing Magisk-patched boot image: patched-boot.img")
        fb_install_bootimg(serial)
        print("Finished flashing boot image.")
        time.sleep(2)
        if query_yes_no("Reboot to system (using fastboot)?") == "yes":
            fb_reboot_system(serial)

    # TODO: if not in fastboot, reboot with adb

    print("All done!")

    Path("boot.img").unlink(True)
    Path("patched-boot.img").unlink(True)

    msg = "Do you want to delete the downloaded OTA zip (and recovery image)?"
    if query_yes_no(msg) == "yes":
        info.fn.unlink(True)
        info.fn_r.unlink(True)


if __name__ == "__main__":
    try:
        main()
        # TODO: when waiting for input(), handling CTRL+C is delayed until after pressing enter for some reason. would be nice if it always stops the program immediately.
    except KeyboardInterrupt:
        print("\nCTRL+C detected, exiting.")
        exit(1)
