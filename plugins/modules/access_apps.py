#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
module: access_apps
short_description: Manage Cloudflare Access applications
description:
  - Create, update, and delete Cloudflare Access applications by name.
  - Secret fields are redacted from returned applications.
version_added: '2.0.0'
author:
  - Taylor Kimball (@tkimball83)
options:
  account_id:
    description:
      - Cloudflare account identifier.
    required: true
    type: str
  api_token:
    description:
      - Cloudflare API token with permissions to manage Access applications.
    required: true
    type: str
  name:
    description:
      - Access application name.
    required: true
    type: str
  domain:
    description:
      - Application domain.
      - Required when O(state=present).
    type: str
  type:
    description:
      - Access application type.
      - Required when O(state=present).
    type: str
  allowed_idps:
    type: list
    elements: str
    description:
      - Identity provider identifiers allowed for the application.
  app_launcher_visible:
    type: bool
    default: true
    description:
      - Whether to show the application in the Access application launcher.
  auto_redirect_to_identity:
    type: bool
    default: false
    description:
      - Whether to redirect users to the identity provider automatically.
  cors_headers:
    type: dict
    description:
      - Cross-origin resource sharing headers for the application.
  custom_deny_message:
    type: str
    description:
      - Message displayed when Access denies a request.
  custom_deny_url:
    type: str
    description:
      - URL used when Access denies a request.
  destinations:
    type: list
    elements: dict
    description:
      - Public destinations protected by the application.
  enable_binding_cookie:
    type: bool
    default: false
    description:
      - Whether to bind the Access cookie to the user session.
  http_only_cookie_attribute:
    type: bool
    default: true
    description:
      - Whether the Access cookie uses the HTTP-only attribute.
  logo_url:
    type: str
    description:
      - URL of the application logo.
  oauth_configuration:
    type: dict
    version_added: '2.2.0'
    description:
      - Managed OAuth settings that make Access the OAuth 2.0 authorization server for the application.
      - Cloudflare documents that an application update overwrites the existing configuration. When the module
        updates an application, it keeps the current Managed OAuth settings that this option does not set.
      - Omitting this option leaves Managed OAuth unmanaged. Set O(oauth_configuration.enabled=false) to turn
        Managed OAuth off. A self-hosted application without Managed OAuth settings matches
        O(oauth_configuration.enabled=false), whatever other suboptions are set.
      - When the current application returns Managed OAuth settings without C(enabled), the module fails
        instead of updating the application unless this option is set, because Cloudflare treats an omitted
        C(enabled) as V(true).
      - The module neither compares nor changes a suboption that is unset. Removing a value from the play keeps
        the current value; the module cannot restore the Cloudflare default.
    suboptions:
      enabled:
        type: bool
        required: true
        description:
          - Whether Access handles OAuth for the application.
          - A current application that does not return this value is reported as changed.
      dynamic_client_registration:
        type: dict
        description:
          - Settings for OAuth dynamic client registration.
          - Cloudflare does not document defaults for unset Boolean suboptions, and its Terraform provider treats
            unset and V(true) as equal. Set O(oauth_configuration.dynamic_client_registration.enabled),
            O(oauth_configuration.dynamic_client_registration.allow_any_on_localhost), and
            O(oauth_configuration.dynamic_client_registration.allow_any_on_loopback) explicitly to pin them.
        suboptions:
          enabled:
            type: bool
            description:
              - Whether dynamic client registration is enabled.
          allow_any_on_localhost:
            type: bool
            description:
              - Whether to allow any client with redirect URIs on C(localhost).
          allow_any_on_loopback:
            type: bool
            description:
              - Whether to allow any client with redirect URIs on C(127.0.0.1).
          allowed_uris:
            type: list
            elements: str
            description:
              - Redirect URIs allowed for dynamically registered clients.
              - HTTP and HTTPS paths may end in C(/*) to match all sub-paths.
              - Custom-scheme URIs must match exactly.
              - An empty list clears the allowed URIs and matches an application that returns none.
      grant:
        type: dict
        description:
          - Settings for OAuth grant behavior.
        suboptions:
          access_token_lifetime:
            type: str
            description:
              - Lifetime of an OAuth access token, such as C(15m) or C(2h45m).
              - Cloudflare documents a default of 15 minutes.
          session_duration:
            type: str
            description:
              - Lifetime of the OAuth grant session and its refresh token, such as C(336h).
  policies:
    type: list
    elements: dict
    description:
      - Access policies attached to the application.
  same_site_cookie_attribute:
    type: str
    description:
      - SameSite attribute for the Access cookie.
  service_auth_401_redirect:
    type: bool
    description:
      - Whether service authentication failures redirect with HTTP 401.
  session_duration:
    type: str
    default: 24h
    description:
      - Maximum duration of an authenticated Access session.
  skip_interstitial:
    type: bool
    description:
      - Whether to skip the Access interstitial page.
  state:
    type: str
    choices:
      - present
      - absent
    default: present
    description:
      - Desired state of the resource.
requirements:
  - python >= 3.9
  - cloudflare >= 5.7.0, < 6
attributes:
  check_mode:
    description: Supports predicting changes without applying them.
    support: full
  diff_mode:
    description: Determines whether the module returns change details in diff format.
    support: none

"""

EXAMPLES = r"""
- name: Ensure Access application exists
  linuxhq.cloudflare.access_apps:
    account_id: "{{ account_id }}"
    api_token: "{{ cloudflare_api_token }}"
    name: app
    domain: app.example.com
    type: self_hosted

- name: Ensure Access application uses Managed OAuth
  linuxhq.cloudflare.access_apps:
    account_id: "{{ account_id }}"
    api_token: "{{ cloudflare_api_token }}"
    name: mcp
    domain: mcp.example.com
    type: self_hosted
    oauth_configuration:
      enabled: true
      dynamic_client_registration:
        enabled: true
        allow_any_on_localhost: false
        allow_any_on_loopback: false
        allowed_uris:
          - https://client.example.com/oauth/callback
      grant:
        access_token_lifetime: 15m
        session_duration: 336h
"""

RETURN = r"""
---
access_app:
  description: Cloudflare Access application.
  returned: when available
  type: dict
  contains:
    id:
      description: Access application identifier.
      returned: always
      type: str
    name:
      description: Access application name.
      returned: always
      type: str
message:
  description: Operation summary.
  returned: always
  type: str

"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.dict_transformations import dict_merge

from ansible_collections.linuxhq.cloudflare.plugins.module_utils.cloudflare_utils import (
    cloudflare_client,
    cloudflare_path,
    delete_result,
    find_by_name,
    normalize_current_by_desired_fields,
    payload_from_params,
    post_result,
    put_result,
    redact_access_app_secrets,
    resource_field,
    resource_id,
    select_fields,
    serialize_resource,
)

FIELDS = (
    "allowed_idps",
    "app_launcher_visible",
    "auto_redirect_to_identity",
    "cors_headers",
    "custom_deny_message",
    "custom_deny_url",
    "destinations",
    "domain",
    "enable_binding_cookie",
    "http_only_cookie_attribute",
    "logo_url",
    "name",
    "oauth_configuration",
    "policies",
    "same_site_cookie_attribute",
    "service_auth_401_redirect",
    "session_duration",
    "skip_interstitial",
    "type",
)

DEFAULT_FIELDS = {
    "app_launcher_visible": True,
    "auto_redirect_to_identity": False,
    "enable_binding_cookie": False,
    "http_only_cookie_attribute": True,
    "session_duration": "24h",
}


def without_unset_values(value):
    if not isinstance(value, dict):
        return value

    values = {key: without_unset_values(item) for key, item in value.items()}

    return {key: item for key, item in values.items() if item is not None and item != {}}


def comparable_access_app(access_app, desired):
    comparable = {**DEFAULT_FIELDS, **access_app}
    requested = desired.get("oauth_configuration")
    if not isinstance(requested, dict):
        return comparable

    current = comparable.get("oauth_configuration")
    if current is None and requested.get("enabled") is False and comparable.get("type") == "self_hosted":
        current = requested

    requested_registration = requested.get("dynamic_client_registration", {})
    if (
        isinstance(current, dict)
        and isinstance(requested_registration, dict)
        and requested_registration.get("allowed_uris") == []
    ):
        registration = current.get("dynamic_client_registration") or {}
        if isinstance(registration, dict) and registration.get("allowed_uris") is None:
            current = {**current, "dynamic_client_registration": {**registration, "allowed_uris": []}}

    comparable["oauth_configuration"] = current

    return comparable


def differing_paths(current, desired, prefix=""):
    if isinstance(current, dict) and isinstance(desired, dict):
        return [
            path
            for key in sorted(set(current) | set(desired))
            for path in differing_paths(current.get(key), desired.get(key), f"{prefix}{key}.")
        ]

    return [] if current == desired else [prefix[:-1]]


def differing_fields(access_app, desired):
    current = normalize_current_by_desired_fields(
        select_fields(comparable_access_app(access_app, desired), desired.keys()),
        desired,
    )

    return differing_paths(serialize_resource(current), serialize_resource(desired))


def validate_applied(module, access_app, desired, app_id):
    fields = differing_fields(access_app, desired)
    if fields:
        module.fail_json(
            msg=(
                f"Cloudflare did not apply the requested Access application {app_id}; "
                f"differing fields: {', '.join(fields)}"
            ),
        )


def update_body(module, current, current_id, payload):
    current_oauth_configuration = current.get("oauth_configuration")
    if current_oauth_configuration is None:
        return payload

    if not isinstance(current_oauth_configuration, dict) or any(
        not isinstance(current_oauth_configuration.get(field), (dict, type(None)))
        for field in ("dynamic_client_registration", "grant")
    ):
        module.fail_json(msg=f"Cloudflare API returned malformed Access application {current_id} data")

    if "oauth_configuration" not in payload and not isinstance(current_oauth_configuration.get("enabled"), bool):
        module.fail_json(
            msg=(
                f"Access application {current_id} returned Managed OAuth settings without enabled; "
                "set oauth_configuration to update it"
            ),
        )

    return {
        **payload,
        "oauth_configuration": without_unset_values(
            dict_merge(current_oauth_configuration, payload.get("oauth_configuration", {}))
        ),
    }


def endpoint(account_id):
    return cloudflare_path("accounts", account_id, "access", "apps")


def item_endpoint(account_id, app_id):
    return cloudflare_path("accounts", account_id, "access", "apps", app_id)


def ensure_present(module, client):
    params = module.params

    current = redact_access_app_secrets(
        find_by_name(
            client,
            endpoint(params["account_id"]),
            params["name"],
            extra_query={"exact": "true"},
            paginate=False,
        )
    )

    payload = payload_from_params(params, FIELDS)
    if "oauth_configuration" in payload:
        payload["oauth_configuration"] = without_unset_values(payload["oauth_configuration"])

    if current is None:
        if module.check_mode:
            module.exit_json(changed=True, message="Access application would be created")

        access_app = post_result(client, endpoint(params["account_id"]), payload)
        app_id = resource_id(module, access_app, "Access application")
        resource_field(module, access_app, "name", "Access application", expected=params["name"])
        validate_applied(module, access_app, payload, app_id)
        module.exit_json(
            changed=True,
            message="Access application created",
            access_app=redact_access_app_secrets(access_app),
        )

    current_id = resource_id(module, current, "Access application")

    if not differing_fields(current, payload):
        module.exit_json(
            changed=False,
            message="Access application already present",
            access_app=current,
        )

    body = update_body(module, current, current_id, payload)

    if module.check_mode:
        module.exit_json(
            changed=True,
            message="Access application would be updated",
            access_app=current,
        )

    access_app = put_result(client, item_endpoint(params["account_id"], current_id), body)
    resource_id(module, access_app, "Access application", expected=current_id)
    resource_field(module, access_app, "name", "Access application", expected=params["name"])
    validate_applied(module, access_app, body, current_id)
    module.exit_json(
        changed=True,
        message="Access application updated",
        access_app=redact_access_app_secrets(access_app),
    )


def ensure_absent(module, client):
    params = module.params

    current = redact_access_app_secrets(
        find_by_name(
            client,
            endpoint(params["account_id"]),
            params["name"],
            extra_query={"exact": "true"},
            paginate=False,
        )
    )

    if current is None:
        module.exit_json(changed=False, message="Access application already absent")

    current_id = resource_id(module, current, "Access application")

    if module.check_mode:
        module.exit_json(
            changed=True,
            message="Access application would be deleted",
            access_app=current,
        )

    delete_result(client, item_endpoint(params["account_id"], current_id), expected_id=current_id)
    module.exit_json(
        changed=True,
        message="Access application deleted",
        access_app=current,
    )


def main():
    module = AnsibleModule(
        argument_spec={
            "account_id": {"required": True, "type": "str"},
            "api_token": {"required": True, "type": "str", "no_log": True},
            "name": {"required": True, "type": "str"},
            "domain": {"type": "str"},
            "type": {"type": "str"},
            "allowed_idps": {"type": "list", "elements": "str"},
            "app_launcher_visible": {"type": "bool", "default": True},
            "auto_redirect_to_identity": {"type": "bool", "default": False},
            "cors_headers": {"type": "dict"},
            "custom_deny_message": {"type": "str"},
            "custom_deny_url": {"type": "str"},
            "destinations": {"type": "list", "elements": "dict"},
            "enable_binding_cookie": {"type": "bool", "default": False},
            "http_only_cookie_attribute": {"type": "bool", "default": True},
            "logo_url": {"type": "str"},
            "oauth_configuration": {
                "type": "dict",
                "options": {
                    "enabled": {"type": "bool", "required": True},
                    "dynamic_client_registration": {
                        "type": "dict",
                        "options": {
                            "enabled": {"type": "bool"},
                            "allow_any_on_localhost": {"type": "bool"},
                            "allow_any_on_loopback": {"type": "bool"},
                            "allowed_uris": {"type": "list", "elements": "str"},
                        },
                    },
                    "grant": {
                        "type": "dict",
                        "options": {
                            "access_token_lifetime": {"type": "str", "no_log": False},
                            "session_duration": {"type": "str"},
                        },
                    },
                },
            },
            "policies": {"type": "list", "elements": "dict"},
            "same_site_cookie_attribute": {"type": "str"},
            "service_auth_401_redirect": {"type": "bool"},
            "session_duration": {"type": "str", "default": "24h"},
            "skip_interstitial": {"type": "bool"},
            "state": {
                "type": "str",
                "choices": ["present", "absent"],
                "default": "present",
            },
        },
        required_if=[("state", "present", ["domain", "type"])],
        supports_check_mode=True,
    )

    with cloudflare_client(module) as client:
        if module.params["state"] == "present":
            ensure_present(module, client)
        else:
            ensure_absent(module, client)


if __name__ == "__main__":
    main()
