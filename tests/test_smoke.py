def test_package_has_public_version() -> None:
    import fde_privacy

    assert fde_privacy.__version__ == "0.1.0"
