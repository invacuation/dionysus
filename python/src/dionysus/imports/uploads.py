"""Shared helpers for bounded scanner report uploads."""

from fastapi import HTTPException, UploadFile, status

UPLOAD_READ_CHUNK_BYTES = 64 * 1024


async def read_limited_upload(report_file: UploadFile, max_bytes: int) -> bytes:
    """Read an upload in bounded chunks and reject files over the configured limit.

    Args:
        report_file: Uploaded scanner report file to read.
        max_bytes: Maximum accepted payload size in bytes.

    Returns:
        The full upload payload when it is within the configured limit.

    Raises:
        HTTPException: If the upload exceeds the configured size limit.
    """

    chunks: list[bytes] = []
    total_bytes = 0
    while chunk := await report_file.read(UPLOAD_READ_CHUNK_BYTES):
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Request body too large",
            )
        chunks.append(chunk)
    return b"".join(chunks)
