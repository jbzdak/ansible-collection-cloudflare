# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from unittest import TestCase
from unittest.mock import patch

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.linuxhq.cloudflare.plugins.modules import access_apps
from ansible_collections.linuxhq.cloudflare.tests.unit.plugins.modules.utils import (
    FakeModule,
    ModuleExit,
    ModuleFail,
)


def params(**updates):
    values = {
        "account_id": "account",
        "name": "app",
        "domain": "app.example.com",
        "type": "self_hosted",
        "app_launcher_visible": True,
        "auto_redirect_to_identity": False,
        "enable_binding_cookie": False,
        "http_only_cookie_attribute": True,
        "session_duration": "24h",
    }
    values.update(updates)
    return values


class AccessAppsTests(TestCase):
    def test_existing_app_with_provider_fields_is_unchanged(self):
        current = {
            "id": "app-id",
            "name": "app",
            "domain": "app.example.com",
            "type": "self_hosted",
            "provider": {"ignored": True},
        }
        module = FakeModule(params())

        with (
            patch.object(access_apps, "find_by_name", return_value=current),
            patch.object(access_apps, "put_result") as put,
            self.assertRaises(ModuleExit) as raised,
        ):
            access_apps.ensure_present(module, {})

        put.assert_not_called()
        self.assertFalse(raised.exception.values["changed"])

    def test_check_mode_does_not_create(self):
        module = FakeModule(params(), check_mode=True)

        with (
            patch.object(access_apps, "find_by_name", return_value=None),
            patch.object(access_apps, "post_result") as post,
            self.assertRaises(ModuleExit) as raised,
        ):
            access_apps.ensure_present(module, {})

        post.assert_not_called()
        self.assertTrue(raised.exception.values["changed"])

    def test_rejects_create_response_with_wrong_configuration(self):
        module = FakeModule(params())

        with (
            patch.object(access_apps, "find_by_name", return_value=None),
            patch.object(
                access_apps,
                "post_result",
                return_value={"id": "app-id", "name": "app"},
            ),
            self.assertRaises(ModuleFail) as raised,
        ):
            access_apps.ensure_present(module, {})

        self.assertIn("did not apply", raised.exception.values["msg"])
        self.assertTrue(raised.exception.values["msg"].endswith("app-id; differing fields: domain, type"))

    def test_deletes_app_and_returns_redacted_state(self):
        current = {
            "id": "app-id",
            "name": "app",
            "scim_config": {"authentication": {"password": "secret"}},
        }
        module = FakeModule(params())

        with (
            patch.object(access_apps, "find_by_name", return_value=current),
            patch.object(access_apps, "delete_result") as delete,
            self.assertRaises(ModuleExit) as raised,
        ):
            access_apps.ensure_absent(module, {})

        delete.assert_called_once_with({}, "/accounts/account/access/apps/app-id", expected_id="app-id")
        self.assertEqual(
            raised.exception.values["access_app"]["scim_config"]["authentication"],
            {},
        )


class ArgumentSpecCaptured(Exception):
    def __init__(self, argument_spec):
        super().__init__()
        self.argument_spec = argument_spec


def capture_argument_spec(**kwargs):
    raise ArgumentSpecCaptured(kwargs["argument_spec"])


def module_argument_spec():
    """Return the real argument spec so tests see required suboptions."""
    try:
        with patch.object(access_apps, "AnsibleModule", side_effect=capture_argument_spec):
            access_apps.main()
    except ArgumentSpecCaptured as captured:
        return captured.argument_spec

    raise AssertionError("main() did not build AnsibleModule")


def validated_params(**updates):
    values = {
        "account_id": "account",
        "api_token": "token",
        "name": "app",
        "domain": "app.example.com",
        "type": "self_hosted",
    }
    values.update(updates)
    result = ArgumentSpecValidator(module_argument_spec()).validate(values)
    if result.error_messages:
        raise AssertionError(result.error_messages)

    return result.validated_parameters


def oauth_app(oauth_configuration):
    return {
        "id": "app-id",
        "name": "app",
        "domain": "app.example.com",
        "type": "self_hosted",
        "oauth_configuration": oauth_configuration,
    }


CURRENT_OAUTH_CONFIGURATION = {
    "enabled": True,
    "dynamic_client_registration": {
        "enabled": True,
        "allow_any_on_localhost": False,
        "allow_any_on_loopback": False,
        "allowed_uris": ["https://client.example.com/oauth/callback"],
    },
    "grant": {"access_token_lifetime": "15m", "session_duration": "24h"},
}


class AccessAppsOAuthConfigurationTests(TestCase):
    def ensure_present(self, module, current, response=None, expected=ModuleExit):
        with (
            patch.object(access_apps, "find_by_name", return_value=current),
            patch.object(access_apps, "post_result", return_value=response) as post,
            patch.object(access_apps, "put_result", return_value=response) as put,
            self.assertRaises(expected) as raised,
        ):
            access_apps.ensure_present(module, {})

        return raised.exception.values, post, put

    def test_enabled_is_required(self):
        with self.assertRaises(AssertionError) as raised:
            validated_params(oauth_configuration={"grant": {"session_duration": "336h"}})

        self.assertIn("enabled", str(raised.exception))

    def test_creates_app_without_unset_suboptions(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={
                    "enabled": True,
                    "dynamic_client_registration": {
                        "enabled": True,
                        "allowed_uris": ["https://client.example.com/oauth/callback"],
                    },
                },
            )
        )

        result, post, _put = self.ensure_present(module, None, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        self.assertEqual(
            post.call_args.args[2]["oauth_configuration"],
            {
                "enabled": True,
                "dynamic_client_registration": {
                    "enabled": True,
                    "allowed_uris": ["https://client.example.com/oauth/callback"],
                },
            },
        )
        self.assertTrue(result["changed"])

    def test_rejects_create_response_without_oauth_configuration(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": True}))
        response = oauth_app(None)
        del response["oauth_configuration"]

        result, _post, _put = self.ensure_present(module, None, response, expected=ModuleFail)

        self.assertIn("did not apply", result["msg"])
        self.assertTrue(result["msg"].endswith("app-id; differing fields: oauth_configuration"))

    def test_matching_oauth_configuration_is_unchanged(self):
        module = FakeModule(validated_params(oauth_configuration=CURRENT_OAUTH_CONFIGURATION))

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        put.assert_not_called()
        self.assertFalse(result["changed"])

    def test_unset_oauth_suboptions_do_not_report_a_change(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={
                    "enabled": True,
                    "dynamic_client_registration": {"enabled": True},
                    "grant": {},
                },
            )
        )

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        put.assert_not_called()
        self.assertFalse(result["changed"])

    def test_unset_dynamic_client_registration_flags_are_unmanaged(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": True}))
        current = {
            **CURRENT_OAUTH_CONFIGURATION,
            "dynamic_client_registration": {
                **CURRENT_OAUTH_CONFIGURATION["dynamic_client_registration"],
                "allow_any_on_localhost": True,
            },
        }

        result, _post, put = self.ensure_present(module, oauth_app(current))

        put.assert_not_called()
        self.assertFalse(result["changed"])

    def test_update_keeps_unset_dynamic_client_registration_flags(self):
        module = FakeModule(validated_params(domain="new.example.com", oauth_configuration={"enabled": True}))
        current = {
            **CURRENT_OAUTH_CONFIGURATION,
            "dynamic_client_registration": {
                **CURRENT_OAUTH_CONFIGURATION["dynamic_client_registration"],
                "allow_any_on_localhost": True,
            },
        }
        response = {**oauth_app(current), "domain": "new.example.com"}

        result, _post, put = self.ensure_present(module, oauth_app(current), response)

        self.assertEqual(put.call_args.args[2]["oauth_configuration"], current)
        self.assertTrue(result["changed"])

    def test_disabled_oauth_is_enabled(self):
        module = FakeModule(
            validated_params(oauth_configuration={"enabled": True, "dynamic_client_registration": {"enabled": True}})
        )
        current = {**CURRENT_OAUTH_CONFIGURATION, "enabled": False}

        result, _post, put = self.ensure_present(
            module,
            oauth_app(current),
            oauth_app(CURRENT_OAUTH_CONFIGURATION),
        )

        self.assertEqual(put.call_args.args[2]["oauth_configuration"], CURRENT_OAUTH_CONFIGURATION)
        self.assertTrue(result["changed"])

    def test_app_without_oauth_configuration_reports_a_change(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": True}), check_mode=True)
        current = oauth_app(None)
        del current["oauth_configuration"]

        result, _post, put = self.ensure_present(module, current)

        put.assert_not_called()
        self.assertTrue(result["changed"])

    def test_current_without_oauth_enabled_reports_a_change(self):
        module = FakeModule(
            validated_params(oauth_configuration={"enabled": True, "dynamic_client_registration": {"enabled": True}}),
            check_mode=True,
        )
        current = {key: value for key, value in CURRENT_OAUTH_CONFIGURATION.items() if key != "enabled"}

        result, _post, put = self.ensure_present(module, oauth_app(current))

        put.assert_not_called()
        self.assertTrue(result["changed"])

    def test_rejects_update_response_without_oauth_enabled(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": True}))
        current = {**CURRENT_OAUTH_CONFIGURATION, "enabled": False}
        response = {key: value for key, value in CURRENT_OAUTH_CONFIGURATION.items() if key != "enabled"}

        result, _post, _put = self.ensure_present(
            module,
            oauth_app(current),
            oauth_app(response),
            expected=ModuleFail,
        )

        self.assertIn("did not apply", result["msg"])
        self.assertIn("app-id", result["msg"])
        self.assertIn("oauth_configuration.enabled", result["msg"])

    def test_update_without_option_keeps_current_oauth_configuration(self):
        module = FakeModule(validated_params(domain="new.example.com"))
        response = {**oauth_app(CURRENT_OAUTH_CONFIGURATION), "domain": "new.example.com"}

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION), response)

        self.assertEqual(put.call_args.args[2]["oauth_configuration"], CURRENT_OAUTH_CONFIGURATION)
        self.assertTrue(result["changed"])

    def test_update_without_option_fails_when_current_enabled_is_missing(self):
        current = {key: value for key, value in CURRENT_OAUTH_CONFIGURATION.items() if key != "enabled"}

        for check_mode in (False, True):
            with self.subTest(check_mode=check_mode):
                module = FakeModule(validated_params(domain="new.example.com"), check_mode=check_mode)

                result, _post, put = self.ensure_present(module, oauth_app(current), expected=ModuleFail)

                put.assert_not_called()
                self.assertIn("app-id", result["msg"])
                self.assertIn("without enabled", result["msg"])

    def test_rejects_update_response_that_drops_carried_oauth_configuration(self):
        module = FakeModule(validated_params(domain="new.example.com"))
        response = {**oauth_app(None), "domain": "new.example.com"}
        del response["oauth_configuration"]

        result, _post, _put = self.ensure_present(
            module,
            oauth_app(CURRENT_OAUTH_CONFIGURATION),
            response,
            expected=ModuleFail,
        )

        self.assertIn("did not apply", result["msg"])
        self.assertTrue(result["msg"].endswith("differing fields: oauth_configuration"))

    def test_disabled_request_matches_app_without_oauth_configuration(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": False}))
        current = oauth_app(None)
        del current["oauth_configuration"]

        result, _post, put = self.ensure_present(module, current)

        put.assert_not_called()
        self.assertFalse(result["changed"])

    def test_disabled_request_accepts_response_without_oauth_configuration(self):
        module = FakeModule(validated_params(domain="new.example.com", oauth_configuration={"enabled": False}))
        current = oauth_app(None)
        del current["oauth_configuration"]
        response = {**current, "domain": "new.example.com"}

        result, _post, put = self.ensure_present(module, current, response)

        self.assertEqual(put.call_args.args[2]["oauth_configuration"], {"enabled": False})
        self.assertTrue(result["changed"])

    def test_disabled_request_on_non_self_hosted_app_without_oauth_configuration_reports_a_change(self):
        module = FakeModule(
            validated_params(type="mcp_portal", oauth_configuration={"enabled": False}),
            check_mode=True,
        )
        current = {**oauth_app(None), "type": "mcp_portal"}
        del current["oauth_configuration"]

        result, _post, put = self.ensure_present(module, current)

        put.assert_not_called()
        self.assertTrue(result["changed"])

    def test_disabling_accepts_response_without_oauth_configuration(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": False}))
        response = oauth_app(None)
        del response["oauth_configuration"]

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION), response)

        self.assertEqual(
            put.call_args.args[2]["oauth_configuration"],
            {**CURRENT_OAUTH_CONFIGURATION, "enabled": False},
        )
        self.assertTrue(result["changed"])

    def test_update_fails_on_malformed_current_oauth_configuration(self):
        for oauth_configuration in (
            True,
            ["x"],
            {"enabled": True, "dynamic_client_registration": ["x"]},
            {"enabled": True, "grant": ""},
        ):
            with self.subTest(oauth_configuration=oauth_configuration):
                module = FakeModule(validated_params(domain="new.example.com"))

                result, _post, put = self.ensure_present(
                    module,
                    oauth_app(oauth_configuration),
                    expected=ModuleFail,
                )

                put.assert_not_called()
                self.assertEqual(result["msg"], "Cloudflare API returned malformed Access application app-id data")

    def test_update_drops_empty_current_oauth_values(self):
        module = FakeModule(validated_params(domain="new.example.com"))
        current = oauth_app({"enabled": True, "grant": {}})
        response = {**oauth_app({"enabled": True, "grant": {"session_duration": "24h"}}), "domain": "new.example.com"}

        result, _post, put = self.ensure_present(module, current, response)

        self.assertEqual(put.call_args.args[2]["oauth_configuration"], {"enabled": True})
        self.assertTrue(result["changed"])

    def test_empty_allowed_uris_matches_missing_list(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={"enabled": True, "dynamic_client_registration": {"allowed_uris": []}},
            )
        )
        registration = {
            key: value
            for key, value in CURRENT_OAUTH_CONFIGURATION["dynamic_client_registration"].items()
            if key != "allowed_uris"
        }
        current = {**CURRENT_OAUTH_CONFIGURATION, "dynamic_client_registration": registration}

        result, _post, put = self.ensure_present(module, oauth_app(current))

        put.assert_not_called()
        self.assertFalse(result["changed"])

    def test_empty_allowed_uris_accepts_response_without_list(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={"enabled": True, "dynamic_client_registration": {"allowed_uris": []}},
            )
        )
        registration = {
            key: value
            for key, value in CURRENT_OAUTH_CONFIGURATION["dynamic_client_registration"].items()
            if key != "allowed_uris"
        }
        response = {**CURRENT_OAUTH_CONFIGURATION, "dynamic_client_registration": registration}

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION), oauth_app(response))

        self.assertEqual(
            put.call_args.args[2]["oauth_configuration"]["dynamic_client_registration"]["allowed_uris"], []
        )
        self.assertTrue(result["changed"])

    def test_dynamic_client_registration_change_is_detected(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={
                    "enabled": True,
                    "dynamic_client_registration": {"enabled": True, "allow_any_on_localhost": True},
                },
            ),
            check_mode=True,
        )

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        put.assert_not_called()
        self.assertTrue(result["changed"])

    def test_disabling_oauth_is_detected(self):
        module = FakeModule(validated_params(oauth_configuration={"enabled": False}), check_mode=True)

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        put.assert_not_called()
        self.assertTrue(result["changed"])

    def test_removed_allowed_uri_is_detected(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={
                    "enabled": True,
                    "dynamic_client_registration": {"enabled": True, "allowed_uris": []},
                },
            ),
            check_mode=True,
        )

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        put.assert_not_called()
        self.assertTrue(result["changed"])

    def test_nested_oauth_change_is_updated(self):
        allowed_uris = ["https://client.example.com/oauth/callback", "https://other.example.com/*"]
        module = FakeModule(
            validated_params(
                oauth_configuration={
                    "enabled": True,
                    "dynamic_client_registration": {"enabled": True, "allowed_uris": allowed_uris},
                    "grant": {"access_token_lifetime": "5m"},
                },
            )
        )
        updated = {
            **CURRENT_OAUTH_CONFIGURATION,
            "dynamic_client_registration": {
                **CURRENT_OAUTH_CONFIGURATION["dynamic_client_registration"],
                "allowed_uris": allowed_uris,
            },
            "grant": {**CURRENT_OAUTH_CONFIGURATION["grant"], "access_token_lifetime": "5m"},
        }

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION), oauth_app(updated))

        self.assertEqual(put.call_args.args[2]["oauth_configuration"], updated)
        self.assertTrue(result["changed"])

    def test_nested_oauth_change_is_predicted_in_check_mode(self):
        module = FakeModule(
            validated_params(
                oauth_configuration={
                    "enabled": True,
                    "dynamic_client_registration": {"enabled": True},
                    "grant": {"session_duration": "336h"},
                },
            ),
            check_mode=True,
        )

        result, _post, put = self.ensure_present(module, oauth_app(CURRENT_OAUTH_CONFIGURATION))

        put.assert_not_called()
        self.assertTrue(result["changed"])
        self.assertEqual(result["message"], "Access application would be updated")
