"""Gerador de fixture sintético idêntico ao formato do tracerpt (T-03).

Usado apenas quando tests/fixtures/kernel.xml (real, sanitizado) não existir.
Reproduz: namespaces do schema de eventos, BOM UTF-8, ProcessId/ParentId em hex e decimal com espaços,
SystemTime com 7 dígitos fracionários, RenderingInfo localizado (pt-BR), cabeçalho EventTrace,
eventos DCStart (rundown), Start e End.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

PROCESS_GUID = "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}"
EVENTTRACE_GUID = "{68fdd900-4a3e-11d1-84f4-0000f80464e3}"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS_TRACE = "http://schemas.microsoft.com/win/2004/08/events/trace"
BASE_TIME = datetime(2026, 11, 8, 21, 47, 0, tzinfo=timezone.utc)
PARENT_PID = 0x91C4
USER = "\\\\HOST-SANITIZADO\\usuario"


def _iso(dt: datetime, extra_100ns: int = 0) -> str:
    frac = dt.microsecond * 10 + extra_100ns
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:07d}00Z"  # 9 dígitos como o tracerpt


def _event(guid: str, opcode: int, opcode_text: str, when: datetime, data: dict, task: str = "",
           event_name: str = "Process", extra_100ns: int = 0) -> str:
    rows = "\n".join(f'\t\t<Data Name="{k}">{escape(str(v))}</Data>' for k, v in data.items())
    return f"""<Event xmlns="{NS}">
\t<System>
\t\t<Provider Guid="{guid}" />
\t\t<EventID>0</EventID>
\t\t<Version>4</Version>
\t\t<Level>0</Level>
\t\t<Task>0</Task>
\t\t<Opcode>{opcode}</Opcode>
\t\t<Keywords>0x0</Keywords>
\t\t<TimeCreated SystemTime="{_iso(when, extra_100ns)}" />
\t\t<Correlation ActivityID="{{00000000-0000-0000-0000-000000000000}}" />
\t\t<Execution ProcessID="4" ThreadID="8" ProcessorID="0" KernelTime="0" UserTime="0" />
\t\t<Channel />
\t\t<Computer />
\t</System>
\t<EventData>
{rows}
\t</EventData>
\t<RenderingInfo Culture="pt-BR">
\t\t<Opcode>{opcode_text}</Opcode>
\t\t<Task>{task}</Task>
\t\t<Provider>MSNT_SystemTrace</Provider>
\t\t<EventName xmlns="{NS_TRACE}">{event_name}</EventName>
\t</RenderingInfo>
\t<ExtendedTracingInfo xmlns="{NS_TRACE}">
\t\t<EventGuid>{guid}</EventGuid>
\t</ExtendedTracingInfo>
</Event>"""


def _proc_data(pid: int, ppid: int, image: str, cmd: str, exit_status: int, hex_ids: bool) -> dict:
    fmt = (lambda v: f"0x{v:X}") if hex_ids else (lambda v: f"{v:>8d}")
    return {
        "UniqueProcessKey": "0xFFFF8F0A1B2C3080", "ProcessId": fmt(pid), "ParentId": fmt(ppid),
        "SessionId": "       1", "ExitStatus": str(exit_status), "DirectoryTableBase": "0x1AB2C3000",
        "Flags": "       0", "UserSID": USER, "ImageFileName": image, "CommandLine": cmd,
        "PackageFullName": "", "ApplicationId": "",
    }


def spike_specs(count: int = 200) -> list[dict]:
    specs = []
    for i in range(count):
        pid = 0x5000 + i * 4
        start = BASE_TIME + timedelta(milliseconds=50 * i + 1000)
        specs.append({"pid": pid, "ppid": PARENT_PID, "image": "cmd.exe",
                      "cmd": f"cmd.exe /c echo SPIKEMARK_{i:04d}", "start": start,
                      "end": start + timedelta(milliseconds=18 + (i % 7)), "hex": i % 2 == 0})
    return specs


def build_xml(count: int = 200) -> str:
    events = [_event(EVENTTRACE_GUID, 0, "Header", BASE_TIME, {"BufferSize": "65536", "Version": "0x0A000000"},
                     task="EventTrace", event_name="EventTrace")]
    events.append(_event(PROCESS_GUID, 3, "DCStart", BASE_TIME + timedelta(milliseconds=1),
                         _proc_data(PARENT_PID, 0x1F00, "python.exe", "python.exe spike.py", 259, True)))
    events.append(_event(PROCESS_GUID, 3, "DCStart", BASE_TIME + timedelta(milliseconds=1),
                         _proc_data(4, 0, "System", "", 259, False)))
    for s in spike_specs(count):
        events.append(_event(PROCESS_GUID, 1, "Start", s["start"],
                             _proc_data(s["pid"], s["ppid"], s["image"], s["cmd"], 259, s["hex"]), extra_100ns=3))
        events.append(_event(PROCESS_GUID, 2, "End", s["end"],
                             _proc_data(s["pid"], s["ppid"], s["image"], s["cmd"], 0, s["hex"]), extra_100ns=7))
    events.append(_event(PROCESS_GUID, 4, "DCEnd", BASE_TIME + timedelta(seconds=20),
                         _proc_data(PARENT_PID, 0x1F00, "python.exe", "python.exe spike.py", 259, True)))
    body = "\n".join(events)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n{body}\n</Events>\n'


def build_csv(count: int = 200) -> str:
    """Layout [HIPÓTESE] do tracerpt -of CSV: cabeçalho por tipo + 'User Data' com campos MOF em ordem."""
    header = ("Event Name, Type, Event ID, Version, Channel, Level, Opcode, Task, Keyword, PID, TID, "
              "Processor Number, Instance ID, Parent Instance ID, Activity ID, Related Activity ID, "
              "Clock-Time, Kernel(ms), User(ms), User Data")
    epoch_ft = lambda dt: int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    lines = [header]
    for s in spike_specs(count):
        for typ, when, status in (("Start", s["start"], 259), ("End", s["end"], 0)):
            d = _proc_data(s["pid"], s["ppid"], s["image"], s["cmd"], status, s["hex"])
            ud = ", ".join(f'"{v}"' if k in ("CommandLine", "UserSID", "ImageFileName") else v.strip() or '""'
                           for k, v in d.items())
            lines.append(f"Process, {typ}, 0, 4, 0, 0, {1 if typ == 'Start' else 2}, 0, 0x0, 4, 8, 0, 0, 0, "
                         f"{{00000000-0000-0000-0000-000000000000}}, , {epoch_ft(when)}, 0, 0, {ud}")
    return "\n".join(lines) + "\n"


def write_fixtures(target_dir: Path, count: int = 200) -> tuple[Path, Path]:
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    xml_path = target_dir / "kernel.xml"
    csv_path = target_dir / "kernel.csv"
    xml_path.write_bytes(b"\xef\xbb\xbf" + build_xml(count).encode("utf-8"))
    csv_path.write_text(build_csv(count), encoding="utf-8")
    return xml_path, csv_path


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "synthetic"
    print(write_fixtures(out))

