"""Build linkage uses bounded metadata without invoking host native tools."""
import struct
import subprocess
import pytest
from cvevidence_core.buildproof import elf_needed
from cvevidence_core.integrity import IntegrityError, safe_extract, ingest_package
from cvevidence_core.partial_intake import create
from tests.test_elf_metadata import example


def package(tmp_path, data):
    create([('product/device', data)], tmp_path/'input.tgz')
    safe_extract(tmp_path/'input.tgz', tmp_path/'input')
    return ingest_package(tmp_path/'input')


@pytest.mark.parametrize('bits,endian', [(32,'>'),(32,'<'),(64,'>'),(64,'<')])
def test_build_dependencies_without_native_process(tmp_path, monkeypatch, bits, endian):
    ctx=package(tmp_path,example(bits,endian))
    def forbidden(*args,**kwargs):
        pytest.fail('Build metadata must not launch native processes')
    monkeypatch.setattr(subprocess,'run',forbidden)
    assert elf_needed(ctx,'product/device')==['libtest.so.1']


@pytest.mark.parametrize('data',[b'not ELF',example()[:-2]])
def test_bad_metadata_rejected_as_integrity_error(tmp_path,data):
    with pytest.raises(IntegrityError,match='unsupported or malformed'):
        elf_needed(package(tmp_path,data),'product/device')


def test_no_dynamic_segment_has_no_declared_dependencies(tmp_path):
    data=bytearray(example())
    struct.pack_into('>I',data,52+32,0)  # PT_NULL replaces PT_DYNAMIC.
    assert elf_needed(package(tmp_path,bytes(data)),'product/device')==[]


def test_mutated_product_is_rejected_before_metadata_read(tmp_path):
    ctx=package(tmp_path,example())
    (ctx.root/'product/device').write_bytes(example(64,'<'))
    with pytest.raises(IntegrityError):elf_needed(ctx,'product/device')


def test_missing_product_is_explicit(tmp_path):
    with pytest.raises(IntegrityError,match='missing'):
        elf_needed(package(tmp_path,example()),'missing')
