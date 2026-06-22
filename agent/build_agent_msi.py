import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
build_exe_options = {
    "packages": ["scapy", "win32serviceutil", "win32service", "win32event", "servicemanager"],
    "excludes": ["tkinter", "unittest"],
    "include_files": [],
}

bdist_msi_options = {
    "add_to_path": True,
    "initial_target_dir": r"[ProgramFilesFolder]\PacketraAgent",
}

setup(
    name="PacketraAgent",
    version="1.0",
    description="Packetra Remote Capture Agent Service",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=[
        Executable(
            "agent_service.py",
            base=None,
            target_name="RemoteCaptureAgent.exe",
        )
    ],
)
