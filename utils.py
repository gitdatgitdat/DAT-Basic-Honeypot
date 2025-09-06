from pathlib import Path
from datetime import datetime, timedelta, timezone
import gzip
import shutil

def rotate_and_compress_logs(log_dir: Path, *,
                             retain_days: int = 7,
                             compress_old: bool = True,
                             compress_after_days: int = 1) -> dict:
    """
    - Gzip compresses *.jsonl / *.log files older than `compress_after_days`
      (skips files already ending in .gz)
    - Deletes any (compressed or not) older than `retain_days`
    Returns counts for a quick summary.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    cutoff_compress = now - timedelta(days=compress_after_days)
    cutoff_delete   = now - timedelta(days=retain_days)

    compressed = 0
    deleted = 0

    def file_mtime_utc(p: Path) -> datetime:
        # Interpret mtime as UTC for comparison
        return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)

    # Consider plain logs and already-compressed logs
    patterns = ["*.jsonl", "*.log", "*.jsonl.gz", "*.log.gz"]
    files = []
    for pat in patterns:
        files.extend(log_dir.glob(pat))

    for f in files:
        try:
            mtime = file_mtime_utc(f)

            # Delete first if beyond retention
            if mtime < cutoff_delete:
                f.unlink(missing_ok=True)
                deleted += 1
                continue

            # Compress if requested and not yet compressed and older than threshold
            if compress_old and f.suffix != ".gz" and mtime < cutoff_compress:
                gz_path = f.with_suffix(f.suffix + ".gz")
                # Don’t overwrite if it somehow exists
                if not gz_path.exists():
                    with f.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    f.unlink(missing_ok=True)
                    compressed += 1

        except Exception:
            # best-effort; ignore a bad file
            pass

    return {"compressed": compressed, "deleted": deleted}
