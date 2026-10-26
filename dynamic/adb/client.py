from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import time
import zlib
import shutil
import re
from typing import ClassVar


@dataclass(frozen=True)
class AdbResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    logcat_format: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class AdbDevice:
    serial: str
    state: str


@dataclass(frozen=True)
class StorageVolume:
    path: str
    total_bytes: int
    used_bytes: int
    available_bytes: int
    used_percent: float


@dataclass(frozen=True)
class StorageBreakdown:
    volume: StorageVolume | None
    video_bytes: int
    image_bytes: int
    other_bytes: int
    scanned_paths: list[str]
    detail: str | None = None


class AdbClient:
    _DESTRUCTIVE_TOP_LEVEL: ClassVar[set[str]] = {"uninstall", "wipe-data", "factory-reset", "format"}
    _DESTRUCTIVE_SHELL: ClassVar[set[tuple[str, ...]]] = {
        ("pm", "clear"),
        ("pm", "uninstall"),
        ("rm", "-rf"),
    }

    def __init__(self, adb_path: Path, default_timeout: int = 60, command_log: list[dict[str, object]] | None = None) -> None:
        discovered = shutil.which("adb") if not adb_path.exists() else None
        self.adb_path = Path(discovered) if discovered else adb_path
        self.default_timeout = default_timeout
        self.command_log = command_log

    def available(self) -> bool:
        return self.adb_path.exists()

    def run(self, args: list[str], timeout: int | None = None, device: str | None = None) -> AdbResult:
        blocked = self._blocked_operation(args)
        if blocked:
            command = [str(self.adb_path), *( ["-s", device] if device else [] ), *args]
            self._audit(command, 126, 0.0)
            return AdbResult(command, 126, "", f"Blocked destructive ADB operation: {blocked}")
        if not self.available():
            command = [str(self.adb_path), *args]
            self._audit(command, 127, 0.0)
            return AdbResult(command, 127, "", f"Missing adb executable: {self.adb_path}")

        command = [str(self.adb_path)]
        if device:
            command.extend(["-s", device])
        command.extend(args)
        return self._run_process(command, timeout or self.default_timeout)

    def _run_process(self, command: list[str], timeout: int) -> AdbResult:
        startupinfo = None
        creationflags = 0
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        process = None
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            stdout, stderr = process.communicate(timeout=timeout)
            result = AdbResult(command, process.returncode, stdout, stderr)
            self._audit(command, result.exit_code, time.monotonic() - started)
            return result
        except subprocess.TimeoutExpired:
            if process is not None:
                self._terminate_process(process)
                stdout, stderr = process.communicate()
            else:
                stdout, stderr = "", ""
            message = (stderr or "").strip()
            if message:
                message = f"{message}{chr(10)}ADB command timed out and was terminated."
            else:
                message = "ADB command timed out and was terminated."
            result = AdbResult(command, -1, stdout or "", message)
            self._audit(command, result.exit_code, time.monotonic() - started)
            return result
        except OSError as exc:
            result = AdbResult(command, 127, "", str(exc))
            self._audit(command, result.exit_code, time.monotonic() - started)
            return result

    def _audit(self, command: list[str], exit_code: int, duration: float) -> None:
        if self.command_log is not None:
            self.command_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "argv": command,
                "exit_code": exit_code,
                "duration_seconds": round(duration, 6),
            })

    @classmethod
    def _blocked_operation(cls, args: list[str]) -> str | None:
        tokens = [str(arg).lower() for arg in args]
        if not tokens:
            return None
        first = next((token for token in tokens if not token.startswith("-")), "")
        if first in cls._DESTRUCTIVE_TOP_LEVEL:
            return first
        if first != "shell":
            return None
        remote = tuple(token for token in tokens[1:] if token not in {"--"})
        for operation in cls._DESTRUCTIVE_SHELL:
            if remote[: len(operation)] == operation:
                return " ".join(operation)
        if remote and remote[0] in cls._DESTRUCTIVE_TOP_LEVEL:
            return remote[0]
        return None

    @staticmethod
    def _terminate_process(process: subprocess.Popen[str]) -> None:
        try:
            process.kill()
        except OSError:
            pass

    def devices(self, timeout: int = 5) -> list[AdbDevice]:
        result = self.run(["devices"], timeout=timeout)
        if not result.ok:
            return []
        devices: list[AdbDevice] = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                devices.append(AdbDevice(serial=parts[0], state=parts[1]))
        return devices

    def first_ready_device(self, preferred_serial: str | None = None, devices: list[AdbDevice] | None = None) -> AdbDevice | None:
        devices = [device for device in (devices if devices is not None else self.devices()) if device.state == "device"]
        if preferred_serial:
            for device in devices:
                if device.serial == preferred_serial:
                    return device
        return devices[0] if devices else None

    def shell(self, command: list[str], device: str, timeout: int | None = None) -> AdbResult:
        return self.run(["shell", *command], timeout=timeout, device=device)

    def storage_summary(self, device: str, timeout: int = 10) -> str:
        """Return package-install storage details without failing the run if unavailable."""
        result = self.shell(["df", "-k", "/data", "/data/local/tmp"], device=device, timeout=timeout)
        return result.stdout or result.stderr

    def storage_breakdown(self, device: str, timeout: int = 20, scan_personal: bool = False) -> StorageBreakdown:
        """Read storage metadata only; never reads file contents or changes the device."""
        volume_result = self.shell(["df", "-k", "/sdcard"], device=device, timeout=timeout)
        volume = self._parse_df(volume_result.stdout, "/sdcard")

        # Android exposes shared storage through /sdcard. These common folders let us
        # provide a useful, privacy-preserving estimate without copying or opening files.
        paths = []
        if scan_personal:
            paths = [
                "/sdcard/Movies",
                "/sdcard/DCIM/Movies",
                "/sdcard/Pictures",
                "/sdcard/DCIM/Camera",
                "/sdcard/DCIM",
            ]
        if not paths:
            return StorageBreakdown(volume, 0, 0, volume.used_bytes if volume else 0, [], None)
        result = self.shell(["du", "-sk", *paths], device=device, timeout=timeout)
        sizes: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2 and parts[0].isdigit():
                sizes[parts[1].strip()] = int(parts[0]) * 1024

        video_bytes = sizes.get("/sdcard/Movies", 0) + sizes.get("/sdcard/DCIM/Movies", 0)
        # DCIM/Camera is included in images only when a device reports it separately;
        # otherwise the broader DCIM value is used as the image estimate.
        image_bytes = sizes.get("/sdcard/Pictures", 0) + sizes.get("/sdcard/DCIM/Camera", 0)
        if not image_bytes:
            image_bytes = sizes.get("/sdcard/DCIM", 0)
        shared_used = volume.used_bytes if volume else 0
        other_bytes = max(shared_used - video_bytes - image_bytes, 0)
        detail = None if result.ok else (result.stderr or "Shared-storage folder scan was unavailable.")
        return StorageBreakdown(volume, video_bytes, image_bytes, other_bytes, paths, detail)

    @staticmethod
    def _parse_df(output: str, path: str) -> StorageVolume | None:
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5 or not parts[1].isdigit() or not parts[2].isdigit() or not parts[3].isdigit():
                continue
            total_kb, used_kb, available_kb = (int(parts[index]) for index in (1, 2, 3))
            percent = parts[4].rstrip("%")
            try:
                used_percent = float(percent)
            except ValueError:
                used_percent = (used_kb / total_kb * 100) if total_kb else 0.0
            return StorageVolume(path, total_kb * 1024, used_kb * 1024, available_kb * 1024, used_percent)
        return None

    def getprop(self, prop: str, device: str, timeout: int = 10) -> str | None:
        result = self.shell(["getprop", prop], device=device, timeout=timeout)
        return result.stdout.strip() if result.ok and result.stdout.strip() else None

    def wait_for_boot_completed(self, device: str, timeout: int = 60) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.getprop("sys.boot_completed", device, timeout=5) == "1":
                return True
            time.sleep(1)
        return False

    def wait_for_package_ready(self, package_name: str, device: str, timeout: int = 30) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            process = self.shell(["pidof", package_name], device=device, timeout=5)
            windows = self.shell(["dumpsys", "window", "windows"], device=device, timeout=8)
            if process.ok and process.stdout.strip() and windows.ok and package_name in windows.stdout:
                return True
            time.sleep(1)
        return False

    def install(self, apk_path: Path, device: str, timeout: int = 180) -> AdbResult:
        return self.run(["install", "-r", str(apk_path)], timeout=timeout, device=device)

    def launch_package(self, package_name: str, device: str, timeout: int = 30) -> AdbResult:
        return self.shell(["monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"], device=device, timeout=timeout)

    def start_activity(self, component: str, device: str, timeout: int = 30) -> AdbResult:
        return self.shell(["am", "start", "-W", "-n", component], device=device, timeout=timeout)

    @staticmethod
    def am_start_succeeded(result: AdbResult) -> bool:
        output = f"{result.stdout}\n{result.stderr}"
        if not result.ok:
            return False
        if re.search(r"(?im)^\s*Status:\s*ok\s*$", output):
            return not re.search(r"(?i)Permission Denial|SecurityException|Error type\s+\d+|Error:\s*Activity class .*does not exist", output)
        return False

    def resolve_service(self, component: str, device: str, timeout: int = 15) -> AdbResult:
        return self.shell(["cmd", "package", "resolve-service", "--brief", "-n", component], device=device, timeout=timeout)

    def resolve_provider(self, authority: str, device: str, timeout: int = 15) -> AdbResult:
        return self.shell(["cmd", "package", "resolve-content-provider", authority], device=device, timeout=timeout)

    def open_deep_link(self, uri: str, package_name: str, device: str, timeout: int = 30) -> AdbResult:
        return self.shell(
            ["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", uri, "-p", package_name],
            device=device,
            timeout=timeout,
        )

    def clear_logcat(self, device: str) -> AdbResult:
        return self.run(["logcat", "-c"], timeout=15, device=device)

    def dump_logcat_format(self, device: str, logcat_format: str, timeout: int = 30) -> AdbResult:
        return self.run(["logcat", "-d", "-v", logcat_format, "-b", "all"], timeout=timeout, device=device)

    def dump_logcat(self, device: str, timeout: int = 30) -> AdbResult:
        for logcat_format in ("threadtime,year", "threadtime", "time"):
            result = self.dump_logcat_format(device, logcat_format, timeout)
            if result.ok:
                return AdbResult(result.command, result.exit_code, result.stdout, result.stderr, logcat_format)
        return result

    def log_marker(self, device: str, marker: str, timeout: int = 10) -> AdbResult:
        if not re.fullmatch(r"[A-Za-z0-9_ .:-]+", marker):
            return AdbResult([], 2, "", "Invalid DY-MASA marker text.")
        return self.shell(["log", "-t", "DYMASA", "-p", "i", marker], device=device, timeout=timeout)

    def screenshot_png(self, device: str, output_path: Path, timeout: int = 30) -> AdbResult:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        command = [str(self.adb_path), "-s", device, "exec-out", "screencap", "-p"]
        if not self.available():
            return AdbResult(command, 127, "", f"Missing adb executable: {self.adb_path}")
        try:
            completed = subprocess.run(command, check=False, capture_output=True, timeout=timeout)
            stderr = completed.stderr.decode("utf-8", errors="ignore") if completed.stderr else ""
            if completed.returncode != 0:
                return AdbResult(command, completed.returncode, "", stderr.strip())
            output_path.write_bytes(completed.stdout)
            if not self._png_has_visible_content(completed.stdout):
                return AdbResult(command, 1, str(output_path), "Screenshot was empty, invalid, or fully black.")
            return AdbResult(command, 0, str(output_path), stderr.strip())
        except subprocess.TimeoutExpired:
            return AdbResult(command, -1, "", "Screenshot capture timed out.")
        except OSError as exc:
            return AdbResult(command, 127, "", str(exc))

    def capture_ready_screenshot(
        self,
        package_name: str,
        device: str,
        output_path: Path,
        timeout: int = 45,
        attempts: int = 6,
    ) -> AdbResult:
        boot_ready = self.wait_for_boot_completed(device, timeout=min(timeout, 60))
        package_ready = self.wait_for_package_ready(package_name, device, timeout=min(timeout, 30))
        deadline = time.monotonic() + timeout
        last_result = AdbResult([], 1, "", "No screenshot attempt was made.")
        for attempt in range(attempts):
            if time.monotonic() >= deadline:
                break
            time.sleep(1 if attempt == 0 else 2)
            last_result = self.screenshot_png(device, output_path, timeout=20)
            if last_result.ok:
                readiness = f"boot_completed={boot_ready}; package_ready={package_ready}; attempts={attempt + 1}"
                return AdbResult(last_result.command, 0, readiness, last_result.stderr)
        detail = f"boot_completed={boot_ready}; package_ready={package_ready}; attempts={attempts}; last={last_result.stderr}"
        return AdbResult(last_result.command, last_result.exit_code, last_result.stdout, detail)

    @staticmethod
    def _png_has_visible_content(data: bytes) -> bool:
        signature = b"\x89PNG\r\n\x1a\n"
        if not data.startswith(signature):
            return False
        position = len(signature)
        width = height = color_type = bit_depth = None
        compressed = bytearray()
        while position + 12 <= len(data):
            length = int.from_bytes(data[position:position + 4], "big")
            chunk_type = data[position + 4:position + 8]
            chunk = data[position + 8:position + 8 + length]
            position += 12 + length
            if chunk_type == b"IHDR" and len(chunk) >= 13:
                width = int.from_bytes(chunk[0:4], "big")
                height = int.from_bytes(chunk[4:8], "big")
                bit_depth = chunk[8]
                color_type = chunk[9]
            elif chunk_type == b"IDAT":
                compressed.extend(chunk)
            elif chunk_type == b"IEND":
                break
        if not width or not height or bit_depth != 8 or color_type not in {0, 2, 4, 6}:
            return False
        try:
            raw = zlib.decompress(bytes(compressed))
        except zlib.error:
            return False
        channels = {0: 1, 2: 3, 4: 2, 6: 4}[color_type]
        stride = width * channels
        if len(raw) < (stride + 1) * height:
            return False
        previous = bytearray(stride)
        total = 0
        non_black = 0
        offset = 0
        # Exclude Android system bars. A screenshot with only status/navigation
        # pixels is not evidence that the application itself rendered.
        content_start = max(1, int(height * 0.06))
        content_end = min(height, int(height * 0.97))
        for row_number in range(height):
            filter_type = raw[offset]
            encoded = raw[offset + 1:offset + 1 + stride]
            offset += stride + 1
            row = bytearray(stride)
            for index, value in enumerate(encoded):
                left = row[index - channels] if index >= channels else 0
                up = previous[index]
                upper_left = previous[index - channels] if index >= channels else 0
                if filter_type == 0:
                    result = value
                elif filter_type == 1:
                    result = (value + left) & 255
                elif filter_type == 2:
                    result = (value + up) & 255
                elif filter_type == 3:
                    result = (value + ((left + up) // 2)) & 255
                elif filter_type == 4:
                    prediction = left + up - upper_left
                    distance_left = abs(prediction - left)
                    distance_up = abs(prediction - up)
                    distance_upper = abs(prediction - upper_left)
                    predictor = left if distance_left <= distance_up and distance_left <= distance_upper else up if distance_up <= distance_upper else upper_left
                    result = (value + predictor) & 255
                else:
                    return False
                row[index] = result
            if content_start <= row_number < content_end:
                for index in range(0, stride, channels):
                    if color_type == 0:
                        brightness = row[index]
                        alpha = 255
                    elif color_type == 2:
                        brightness = sum(row[index:index + 3]) // 3
                        alpha = 255
                    elif color_type == 4:
                        brightness = row[index]
                        alpha = row[index + 1]
                    else:
                        brightness = sum(row[index:index + 3]) // 3
                        alpha = row[index + 3]
                    total += 1
                    if alpha > 8 and brightness > 8:
                        non_black += 1
            previous = row
        return total > 0 and non_black / total >= 0.002
