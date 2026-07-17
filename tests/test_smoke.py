def test_package_has_public_version() -> None:
    import fde_privacy

    assert fde_privacy.__version__ == "0.1.0"


def test_presidio_anonymizer_uses_patched_cryptography() -> None:
    from importlib.metadata import version

    from presidio_anonymizer import AnonymizerEngine

    engine = AnonymizerEngine()
    cryptography_version = tuple(int(part) for part in version("cryptography").split("."))

    assert isinstance(engine, AnonymizerEngine)
    assert cryptography_version >= (48, 0, 1)
