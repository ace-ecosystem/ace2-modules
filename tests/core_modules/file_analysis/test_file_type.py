# vim: ts=4:sw=4:et:cc=120

import pytest

from core_modules.file_analysis.file_type import FileTypeAnalyzer


@pytest.mark.asyncio
@pytest.mark.unit
async def test_analysis(tmpdir, system, root):

    module = FileTypeAnalyzer()

    target_path = str(tmpdir / "text.txt")
    with open(target_path, "w") as fp:
        fp.write("test")

    observable = await root.add_file(target_path)
    analysis = observable.add_analysis(type=module.type, details={})

    await module.execute_analysis(root, observable, analysis)
