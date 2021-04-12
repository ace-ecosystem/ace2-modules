# vim: ts=4:sw=4:et:cc=120

import asyncio

from core_modules.file_analysis import (
    is_office_ext,
    is_office_file,
    is_macro_ext,
    is_ole_file,
    is_rtf_file,
    is_pdf_file,
    is_pe_file,
    is_zip_file,
)

from ace.analysis import RootAnalysis, FileObservable, Analysis, AnalysisModuleType
from ace.logging import get_logger
from ace.module.base import AnalysisModule


class FileTypeAnalyzer(AnalysisModule):

    type = AnalysisModuleType(
        name="File Type Analyzer",
        description="""Analyzes a file using the file unix command. Performs
        some basic heuristics against known malicious document types.""",
        observable_types=["file"],
        version="1.0.0",
        cache_ttl=60 * 60 * 24 * 30,  # 30 days
        types=["file"],
    )

    async def execute_analysis(
        self, root: RootAnalysis, observable: FileObservable, analysis: Analysis
    ):

        get_logger().debug(f"analyzing for file type {observable.path}")

        # get the human readable
        p = await asyncio.create_subprocess_exec(
            "file",
            "-b",
            "-L",
            observable.path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await p.communicate()

        if len(stderr) > 0:
            get_logger().warning(
                f"file command returned error output for {observable.path}"
            )

        details = {}
        details["type"] = stdout.decode().strip()

        # get the mime type
        p = await asyncio.create_subprocess_exec(
            "file",
            "-b",
            "--mime-type",
            "-L",
            observable.path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await p.communicate()

        if len(stderr) > 0:
            get_logger().warning(
                f"file command returned error output for {observable.path}"
            )

        details["mime"] = stdout.decode().strip()

        analysis.summary = f"{details['type']} ({details['mime']})"

        details["is_office_ext"] = is_office_ext(observable.path)
        details["is_ole_file"] = is_ole_file(observable.path)
        details["is_rtf_file"] = is_rtf_file(observable.path)
        details["is_pdf_file"] = is_pdf_file(observable.path)
        details["is_pe_file"] = is_pe_file(observable.path)
        details["is_zip_file"] = is_zip_file(observable.path)

        is_office_document = details["is_office_ext"]
        is_office_document |= "microsoft powerpoint" in details["type"].lower()
        is_office_document |= "microsoft excel" in details["type"].lower()
        is_office_document |= "microsoft word" in details["type"].lower()
        is_office_document |= "microsoft ooxml" in details["type"].lower()
        is_office_document |= details["is_ole_file"]
        is_office_document |= details["is_rtf_file"]
        details["is_office_document"] = is_office_document

        # perform some additional analysis for some things we care about

        if is_office_document:
            _file.add_tag("microsoft_office")

        if details["is_ole_file"]:
            _file.add_tag("ole")

        if details["is_rtf_file"]:
            _file.add_tag("rtf")

        if details["is_pdf_file"]:
            _file.add_tag("pdf")

        if details["is_pe_file"]:
            _file.add_tag("executable")

        if details["is_zip_file"]:
            _file.add_tag("zip")

        analysis.set_details(details)
        return True
