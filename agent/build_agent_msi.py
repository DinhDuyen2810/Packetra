import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
build_exe_options = {
    "packages": ["scapy", "win32serviceutil", "win32service", "win32event", "servicemanager", "win32timezone"],
    "excludes": ["tkinter", "unittest"],
    "include_files": [],
}

bdist_msi_options = {
    "add_to_path": True,
    "all_users": True,
    "initial_target_dir": r"[ProgramFilesFolder]\PacketraAgent",
    "data": {
        "CustomAction": [
            (
                "A_BOOTSTRAP_AGENT_INSTALL",
                3090,
                "RemoteCaptureAgent.exe",
                "--bootstrap-install",
            ),
            (
                "A_BOOTSTRAP_AGENT_UNINSTALL",
                3346,
                "RemoteCaptureAgent.exe",
                "--bootstrap-uninstall",
            ),
        ],
        "InstallExecuteSequence": [
            (
                "A_BOOTSTRAP_AGENT_UNINSTALL",
                'REMOVE="ALL"',
                3490,
            ),
            (
                "A_BOOTSTRAP_AGENT_INSTALL",
                'NOT REMOVE="ALL"',
                6501,
            ),
        ],
    },
}

setup(
    name="PacketraAgent",
    version="1.6",
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
