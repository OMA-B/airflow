from providers.core import CoreTransform


class TestCoreTransform:
    def test_init(self, engine):
        transform = CoreTransform(engine)
