"""Tests for SystemSettings model."""

from app.models.system import SystemSettings


class TestSystemSettingsDefaults:
    """SystemSettings default values for all field groups."""

    def test_id_defaults_to_current(self):
        """Default id is 'current'."""
        s = SystemSettings()
        assert s.id == "current"

    def test_general_defaults(self):
        """instance_name defaults to 'Dependency Control'."""
        s = SystemSettings()
        assert s.instance_name == "Dependency Control"

    def test_limits_defaults(self):
        """project_limit_per_user defaults to 0 (unlimited)."""
        s = SystemSettings()
        assert s.project_limit_per_user == 0

    def test_security_defaults(self):
        """Security booleans default to False."""
        s = SystemSettings()
        assert s.allow_public_registration is False
        assert s.enforce_2fa is False
        assert s.enforce_email_verification is False

    def test_smtp_defaults(self):
        """SMTP fields have correct defaults."""
        s = SystemSettings()
        assert s.smtp_host is None
        assert s.smtp_port == 587
        assert s.smtp_user is None
        assert s.smtp_password is None
        assert s.smtp_encryption == "starttls"
        assert s.emails_from_email == "info@dependencycontrol.local"
        assert s.emails_from_name == "Dependency Control"

    def test_integration_tokens_default_none(self):
        """Integration token fields default to None."""
        s = SystemSettings()
        assert s.github_token is None
        assert s.open_source_malware_api_key is None
        assert s.slack_bot_token is None
        assert s.slack_client_id is None
        assert s.slack_client_secret is None
        assert s.slack_refresh_token is None
        assert s.slack_token_expires_at is None
        assert s.mattermost_bot_token is None
        assert s.mattermost_url is None

    def test_oidc_defaults(self):
        """OIDC fields have correct defaults."""
        s = SystemSettings()
        assert s.oidc_enabled is False
        assert s.oidc_provider_name == "GitLab"
        assert s.oidc_client_id is None
        assert s.oidc_client_secret is None
        assert s.oidc_issuer is None
        assert s.oidc_authorization_endpoint is None
        assert s.oidc_token_endpoint is None
        assert s.oidc_userinfo_endpoint is None
        assert s.oidc_scopes == "openid profile email"

    def test_gitlab_integration_defaults(self):
        """GitLab integration fields have correct defaults."""
        s = SystemSettings()
        assert s.gitlab_integration_enabled is False
        assert s.gitlab_url == "https://gitlab.com"
        assert s.gitlab_access_token is None
        assert s.gitlab_auto_create_projects is False
        assert s.gitlab_sync_teams is False
        assert s.gitlab_oidc_audience is None

    def test_rescan_defaults(self):
        """Periodic scanning defaults are correct."""
        s = SystemSettings()
        assert s.rescan_mode == "project"
        assert s.global_rescan_enabled is False
        assert s.global_rescan_interval == 24

    def test_default_active_analyzers(self):
        """default_active_analyzers has the expected list."""
        s = SystemSettings()
        assert s.default_active_analyzers == [
            "trivy", "osv", "license_compliance", "end_of_life"
        ]

    def test_retention_defaults(self):
        """Retention fields have correct defaults."""
        s = SystemSettings()
        assert s.retention_mode == "project"
        assert s.global_retention_days == 90


class TestSystemSettingsCustomValues:
    """SystemSettings with explicit custom values."""

    def test_custom_instance_name(self):
        """instance_name can be overridden."""
        s = SystemSettings(instance_name="My Corp Security")
        assert s.instance_name == "My Corp Security"

    def test_custom_security_flags(self):
        """Security booleans can be set to True."""
        s = SystemSettings(
            allow_public_registration=True,
            enforce_2fa=True,
            enforce_email_verification=True,
        )
        assert s.allow_public_registration is True
        assert s.enforce_2fa is True
        assert s.enforce_email_verification is True

    def test_custom_smtp_config(self):
        """SMTP fields can be fully configured."""
        s = SystemSettings(
            smtp_host="mail.example.com",
            smtp_port=465,
            smtp_user="user@example.com",
            smtp_password="secret",
            smtp_encryption="ssl",
            emails_from_email="noreply@example.com",
            emails_from_name="SecOps",
        )
        assert s.smtp_host == "mail.example.com"
        assert s.smtp_port == 465
        assert s.smtp_encryption == "ssl"
        assert s.emails_from_email == "noreply@example.com"

    def test_custom_analyzers_list(self):
        """default_active_analyzers can be set to a custom list."""
        custom = ["trivy", "osv"]
        s = SystemSettings(default_active_analyzers=custom)
        assert s.default_active_analyzers == custom

    def test_empty_analyzers_list(self):
        """default_active_analyzers can be set to an empty list."""
        s = SystemSettings(default_active_analyzers=[])
        assert s.default_active_analyzers == []

    def test_custom_retention(self):
        """Retention values can be overridden."""
        s = SystemSettings(
            retention_mode="global",
            global_retention_days=365,
        )
        assert s.retention_mode == "global"
        assert s.global_retention_days == 365

    def test_zero_retention_means_forever(self):
        """global_retention_days=0 means keep forever."""
        s = SystemSettings(global_retention_days=0)
        assert s.global_retention_days == 0


class TestSystemSettingsIdAlias:
    """SystemSettings _id alias round-trip for MongoDB compatibility."""

    def test_model_dump_by_alias_contains_id(self):
        """model_dump(by_alias=True) produces '_id' key."""
        s = SystemSettings()
        dumped = s.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == "current"

    def test_accepts_id_from_mongo(self):
        """SystemSettings accepts _id via validation_alias."""
        s = SystemSettings(_id="current")
        assert s.id == "current"

    def test_from_mongo_document(self):
        """SystemSettings can be constructed from a MongoDB document."""
        doc = {
            "_id": "current",
            "instance_name": "My Instance",
            "enforce_2fa": True,
            "smtp_port": 465,
        }
        s = SystemSettings(**doc)
        assert s.id == "current"
        assert s.instance_name == "My Instance"
        assert s.enforce_2fa is True
        assert s.smtp_port == 465

    def test_roundtrip_via_model_dump(self):
        """SystemSettings survives model_dump -> reconstruct cycle."""
        original = SystemSettings(
            instance_name="RoundTrip Test",
            enforce_2fa=True,
            default_active_analyzers=["trivy"],
            global_retention_days=180,
        )
        dumped = original.model_dump(by_alias=True)
        restored = SystemSettings(**dumped)
        assert restored.id == original.id
        assert restored.instance_name == "RoundTrip Test"
        assert restored.enforce_2fa is True
        assert restored.default_active_analyzers == ["trivy"]
        assert restored.global_retention_days == 180

    def test_legacy_mongo_doc_without_new_fields(self):
        """Older MongoDB docs missing newer fields get Pydantic defaults."""
        legacy_doc = {
            "_id": "current",
            "instance_name": "Legacy",
        }
        s = SystemSettings(**legacy_doc)
        assert s.default_active_analyzers == [
            "trivy", "osv", "license_compliance", "end_of_life"
        ]
        assert s.gitlab_oidc_audience is None
        assert s.retention_mode == "project"
