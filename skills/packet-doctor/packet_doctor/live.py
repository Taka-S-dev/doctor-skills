"""Finite, non-overwriting dumpcap sessions with sealed-file analysis."""
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import time
import uuid

from .capture import find_tool, run_tool
from .investigation import analyze
from .models import InvestigationError, digest, write_json


def interfaces(dumpcap=None):
    tool = find_tool("dumpcap", dumpcap)
    if not tool:
        raise InvestigationError("dumpcapがありません。Wiresharkと取得ドライバーを導入してください", "tool_missing")
    return {"tool": tool, "interfaces": run_tool([tool, "-D"], timeout=15)}


def closed_files(directory, finished=False):
    files = sorted(Path(directory).glob("capture_*.pcapng"))
    # Creation of the successor is the rotation boundary. The active file is excluded.
    return files if finished else files[:-1]


def distinct_files(files):
    """Idle periods produce byte-identical empty chunks, which analysis rejects as duplicates."""
    return list({digest(f): f for f in reversed(files)}.values())[::-1]


def build_command(tool, interface, output, duration, chunk_seconds, max_files, capture_filter=None):
    if not 1 <= duration <= 3600 or not 1 <= chunk_seconds <= 60 or not 2 <= max_files <= 64:
        raise InvestigationError("duration=1〜3600、chunk-seconds=1〜60、max-files=2〜64の範囲で指定してください")
    command = [tool, "-i", str(interface), "-w", str(output), "-F", "pcapng",
               "-b", f"duration:{chunk_seconds}", "-b", "filesize:8192",
               "-a", f"duration:{duration}", "-a", f"files:{max_files}"]
    if capture_filter:
        command.extend(["-f", capture_filter])
    return command


def capture_live(case_dir, interface, duration=60, chunk_seconds=5, max_files=24, capture_filter=None,
                 dumpcap=None, progress=None, **analysis_options):
    tool = find_tool("dumpcap", dumpcap)
    if not tool:
        raise InvestigationError("ライブ取得にはWiresharkのdumpcapが必要です。check-envで確認してください", "tool_missing")
    root = Path(case_dir).resolve()
    session = root / "live" / (datetime.now(timezone.utc).strftime("session-%Y%m%dT%H%M%S-") + uuid.uuid4().hex[:8])
    command = build_command(tool, interface, session / "capture.pcapng", duration, chunk_seconds, max_files, capture_filter)
    session.mkdir(parents=True)
    metadata = {"command": command, "status": "running", "interface": str(interface),
                "warnings": ["同一観測点の有限セッション。ファイルは循環上書きせず保存します",
                             "保存済み全チャンクを再解析する初期実装。表示更新には解析時間が加わります",
                             "ドロップ数はdumpcap.logで確認してください"]}
    write_json(session / "session.json", metadata)
    previous, result, interrupted = (), None, False
    process = None
    try:
        with (session / "dumpcap.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            started = time.monotonic()
            try:
                while process.poll() is None:
                    files = distinct_files(closed_files(session))
                    key = tuple(str(f) for f in files)
                    if files and key != previous:
                        result = analyze(root, files, **analysis_options)
                        previous = key
                        if progress:
                            progress({"event": "updated", "sealed_files": len(files), "reports": result["reports"]})
                    if time.monotonic() - started > duration + 30:
                        raise InvestigationError("取得プロセスが停止期限を超えました", "timeout")
                    time.sleep(0.5)
            except KeyboardInterrupt:
                interrupted = True
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            clean = process.returncode == 0 and not interrupted
            files = distinct_files(closed_files(session, finished=clean))
            if files and tuple(str(f) for f in files) != previous:
                result = analyze(root, files, **analysis_options)
            metadata.update(status="complete" if clean else "interrupted" if interrupted else "failed",
                            returncode=process.returncode, sealed_files=[str(f) for f in files],
                            latest_report=result["reports"] if result else None)
            write_json(session / "session.json", metadata)
            if not clean and not interrupted:
                raise InvestigationError(f"dumpcap取得失敗。ログ: {session / 'dumpcap.log'}", "tool_failed")
            return {"session": str(session), "status": metadata["status"], "analysis": result,
                    "warnings": metadata["warnings"] + (["中断時の最終ファイルは不完全な可能性があるため解析から除外しました"] if interrupted else [])}
    except Exception as exc:
        metadata.update(status="failed", error=str(exc))
        write_json(session / "session.json", metadata)
        raise
