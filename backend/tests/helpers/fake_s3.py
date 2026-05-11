"""In-memory fake aiobotocore S3 client for archive tests."""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional


class FakeS3StreamingBody:
    """Mimics aiobotocore's StreamingBody."""

    def __init__(self, data: bytes):
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def read(self) -> bytes:
        return self._data

    async def iter_chunks(self, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        for i in range(0, len(self._data), chunk_size):
            yield self._data[i : i + chunk_size]


class FakeS3Client:
    """Records and serves S3 operations from in-memory state."""

    def __init__(self) -> None:
        self.objects: Dict[str, bytes] = {}  # key -> body
        self.bucket_exists: bool = True
        self._multipart_uploads: Dict[str, List[bytes]] = {}  # upload_id -> parts
        self._multipart_keys: Dict[str, str] = {}  # upload_id -> key
        self.aborted_uploads: List[str] = []
        self.put_calls: List[Dict[str, Any]] = []
        self.delete_calls: List[Dict[str, Any]] = []
        self.fail_next_upload_part: bool = False

    async def head_bucket(self, Bucket: str) -> Dict[str, Any]:
        if not self.bucket_exists:
            raise RuntimeError("NoSuchBucket")
        return {}

    async def create_bucket(self, Bucket: str) -> Dict[str, Any]:
        self.bucket_exists = True
        return {}

    async def put_object(self, Bucket: str, Key: str, Body: bytes, ContentType: str = "") -> Dict[str, Any]:
        self.put_calls.append({"Bucket": Bucket, "Key": Key, "ContentType": ContentType})
        self.objects[Key] = bytes(Body)
        return {}

    async def get_object(self, Bucket: str, Key: str) -> Dict[str, Any]:
        if Key not in self.objects:
            raise RuntimeError("NoSuchKey")
        return {"Body": FakeS3StreamingBody(self.objects[Key])}

    async def delete_object(self, Bucket: str, Key: str) -> Dict[str, Any]:
        self.delete_calls.append({"Bucket": Bucket, "Key": Key})
        self.objects.pop(Key, None)
        return {}

    async def list_objects_v2(self, Bucket: str, Prefix: str = "") -> Dict[str, Any]:
        contents = [
            {"Key": k, "Size": len(v)}
            for k, v in self.objects.items()
            if k.startswith(Prefix)
        ]
        return {"Contents": contents, "KeyCount": len(contents)}

    async def create_multipart_upload(self, Bucket: str, Key: str, ContentType: str = "") -> Dict[str, Any]:
        upload_id = f"upload-{len(self._multipart_uploads) + 1}"
        self._multipart_uploads[upload_id] = []
        self._multipart_keys[upload_id] = Key
        return {"UploadId": upload_id}

    async def upload_part(
        self, Bucket: str, Key: str, UploadId: str, PartNumber: int, Body: bytes
    ) -> Dict[str, Any]:
        if self.fail_next_upload_part:
            self.fail_next_upload_part = False
            raise RuntimeError("simulated S3 error on upload_part")
        parts = self._multipart_uploads[UploadId]
        while len(parts) < PartNumber:
            parts.append(b"")
        parts[PartNumber - 1] = bytes(Body)
        return {"ETag": f'"etag-{PartNumber}"'}

    async def complete_multipart_upload(
        self, Bucket: str, Key: str, UploadId: str, MultipartUpload: Dict[str, Any]
    ) -> Dict[str, Any]:
        parts = self._multipart_uploads.pop(UploadId)
        self._multipart_keys.pop(UploadId, None)
        self.objects[Key] = b"".join(parts)
        return {}

    async def abort_multipart_upload(self, Bucket: str, Key: str, UploadId: str) -> Dict[str, Any]:
        self.aborted_uploads.append(UploadId)
        self._multipart_uploads.pop(UploadId, None)
        self._multipart_keys.pop(UploadId, None)
        return {}


@asynccontextmanager
async def fake_get_s3_client(fake: FakeS3Client):
    """Context manager replacement for get_s3_client."""
    yield fake
