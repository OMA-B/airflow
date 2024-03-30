from providers.qualys.qualys import QualysTransform


class TestQualysTransform:
    detections_fp = "tests/data/qualys/qualys_detections.xml"
    knowledgebase_fp = "tests/data/qualys/qualys_knowledgebase.xml"

    def test_init(self, engine):
        transform = QualysTransform(engine)

        assert transform is not None

    def test_process_knowledge_base(self, engine):
        transform = QualysTransform(engine)

        transform.process_knowledge_base(self.knowledgebase_fp)

    def test_process_findings(self, engine):
        transform = QualysTransform(engine)

        transform.process_findings(self.detections_fp)
