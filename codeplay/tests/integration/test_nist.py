import os

from providers.nist.nist import NISTTransform


class TestNISTTransform:
    nvdcve_fp = "tests/data/nvdcve"
    cwe_fp = "tests/data/cwe/1000.csv"

    def test_init(self, engine):
        transform = NISTTransform(engine)

        assert transform is not None

    def test_process_cwe(self, engine):
        transform = NISTTransform(engine, immediately_raise_error=True)

        transform.process_cwe(self.cwe_fp)

    def test_process_cve(self, engine):
        transform = NISTTransform(engine, immediately_raise_error=True)

        for root, _, filenames in os.walk(self.nvdcve_fp):
            for file in filenames:
                fp = str(os.path.join(root, file))
                transform.process_cve(fp)
