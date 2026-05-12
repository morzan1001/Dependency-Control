import pytest

from tests.helpers.fake_s3 import FakeS3Client


@pytest.mark.asyncio
async def test_put_get_delete_roundtrip():
    fake = FakeS3Client()
    await fake.put_object(Bucket="b", Key="k", Body=b"hello")
    obj = await fake.get_object(Bucket="b", Key="k")
    async with obj["Body"] as stream:
        assert await stream.read() == b"hello"
    await fake.delete_object(Bucket="b", Key="k")
    assert "k" not in fake.objects


@pytest.mark.asyncio
async def test_multipart_upload_roundtrip():
    fake = FakeS3Client()
    r = await fake.create_multipart_upload(Bucket="b", Key="k")
    uid = r["UploadId"]
    await fake.upload_part(Bucket="b", Key="k", UploadId=uid, PartNumber=1, Body=b"AAA")
    await fake.upload_part(Bucket="b", Key="k", UploadId=uid, PartNumber=2, Body=b"BBB")
    await fake.complete_multipart_upload(
        Bucket="b", Key="k", UploadId=uid, MultipartUpload={"Parts": []}
    )
    assert fake.objects["k"] == b"AAABBB"
