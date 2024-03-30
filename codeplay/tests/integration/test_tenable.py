from providers.tenable.tenable import TenableTransform


class TestTenableTransform:
    analysis_fp = "tests/data/tenable/analysis.json"
    plugins_fp = "tests/data/tenable/plugins.json"
    solutions_fp = "tests/data/tenable/solutions.json"

    def test_init(self, engine):
        transform = TenableTransform(engine)

        assert transform is not None

    def test_process_plugins(self, engine):
        transform = TenableTransform(engine, immediately_raise_error=True)

        transform.process_plugins(self.plugins_fp)

    def test_process_solutions(self, engine):
        transform = TenableTransform(engine, immediately_raise_error=True)

        transform.process_solutions(self.solutions_fp)

    def test_process_findings(self, engine):
        transform = TenableTransform(engine)

        transform.process_findings(self.analysis_fp)
