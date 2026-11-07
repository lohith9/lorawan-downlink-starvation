"""Provision a tenant, application, Class-A ABP device profile, one gateway and a set of devices on a local
ChirpStack server over its gRPC API, then write integration/devices.json (DevAddr, session keys, tenant)
for the virtual gateway and the orchestrator.

ABP is used so the harness holds the session keys and can build authenticated uplinks without a join. Frame
counters are not checked at the server (skip_fcnt_check) so scenarios can be replayed.

Tested against chirpstack-api==4.9.0 and a ChirpStack v4.19.2 server (see integration/requirements.txt).
Default admin credentials of the official chirpstack-docker deployment are used to obtain a token.
"""
from __future__ import annotations

import json
import os
import secrets

import grpc
from chirpstack_api import api, common

SERVER = os.environ.get("CHIRPSTACK_API", "localhost:8080")
GATEWAY_EUI = "0011223344556677"

# A small, named device set. The orchestrator drives the traffic; counts here only need to show server
# behaviour, not reproduce the 1000-device cell. One attacker holds valid parking-sensor keys.
DEVICES = (
    [("honest-street-%d" % i, "streetlight") for i in range(2)]
    + [("honest-water-%d" % i, "water") for i in range(2)]
    + [("honest-parking-%d" % i, "parking") for i in range(4)]
    + [("honest-waste-%d" % i, "waste") for i in range(2)]
    + [("attacker-parking-sf7", "parking")]
)


def _meta(token: str):
    return [("authorization", "Bearer %s" % token)]


def login(ch) -> str:
    stub = api.InternalServiceStub(ch)
    resp = stub.Login(api.LoginRequest(email="admin", password="admin"))
    return resp.jwt


def ensure_tenant(ch, token) -> str:
    stub = api.TenantServiceStub(ch)
    # reuse the default tenant if present, else create one
    for t in stub.List(api.ListTenantsRequest(limit=10), metadata=_meta(token)).result:
        if t.name in ("ChirpStack", "DLGuard"):
            return t.id
    req = api.CreateTenantRequest(tenant=api.Tenant(name="DLGuard", can_have_gateways=True,
                                                    max_gateway_count=5, max_device_count=100))
    return stub.Create(req, metadata=_meta(token)).id


def ensure_app(ch, token, tenant_id) -> str:
    stub = api.ApplicationServiceStub(ch)
    for a in stub.List(api.ListApplicationsRequest(tenant_id=tenant_id, limit=20),
                       metadata=_meta(token)).result:
        if a.name == "dlguard-itest":
            return a.id
    return stub.Create(api.CreateApplicationRequest(
        application=api.Application(tenant_id=tenant_id, name="dlguard-itest")), metadata=_meta(token)).id


def ensure_device_profile(ch, token, tenant_id) -> str:
    stub = api.DeviceProfileServiceStub(ch)
    for p in stub.List(api.ListDeviceProfilesRequest(tenant_id=tenant_id, limit=20),
                       metadata=_meta(token)).result:
        if p.name == "classA-abp-eu868":
            return p.id
    dp = api.DeviceProfile(
        tenant_id=tenant_id, name="classA-abp-eu868", region=common.Region.EU868,
        mac_version=common.MacVersion.LORAWAN_1_0_3, reg_params_revision=common.RegParamsRevision.A,
        supports_otaa=False, adr_algorithm_id="default", uplink_interval=3600, flush_queue_on_activate=True,
    )
    return stub.Create(api.CreateDeviceProfileRequest(device_profile=dp), metadata=_meta(token)).id


def ensure_gateway(ch, token, tenant_id):
    stub = api.GatewayServiceStub(ch)
    try:
        stub.Create(api.CreateGatewayRequest(gateway=api.Gateway(
            gateway_id=GATEWAY_EUI, name="virtual-gw", tenant_id=tenant_id)), metadata=_meta(token))
    except grpc.RpcError as e:
        if e.code() != grpc.StatusCode.ALREADY_EXISTS:
            raise


def create_device(ch, token, app_id, dp_id, name) -> dict:
    dstub = api.DeviceServiceStub(ch)
    dev_eui = secrets.token_hex(8)
    try:
        dstub.Create(api.CreateDeviceRequest(device=api.Device(
            dev_eui=dev_eui, name=name, application_id=app_id, device_profile_id=dp_id,
            skip_fcnt_check=True, is_disabled=False)), metadata=_meta(token))
    except grpc.RpcError as e:
        if e.code() != grpc.StatusCode.ALREADY_EXISTS:
            raise
    devaddr = secrets.token_hex(4)
    nwkskey = secrets.token_hex(16)
    appskey = secrets.token_hex(16)
    act = api.DeviceActivation(
        dev_eui=dev_eui, dev_addr=devaddr, app_s_key=appskey,
        nwk_s_enc_key=nwkskey, s_nwk_s_int_key=nwkskey, f_nwk_s_int_key=nwkskey,
        f_cnt_up=0, n_f_cnt_down=0, a_f_cnt_down=0)
    dstub.Activate(api.ActivateDeviceRequest(device_activation=act), metadata=_meta(token))
    return {"name": name, "dev_eui": dev_eui, "devaddr": int(devaddr, 16),
            "nwkskey": nwkskey, "appskey": appskey}


def main():
    ch = grpc.insecure_channel(SERVER)
    token = login(ch)
    tenant_id = ensure_tenant(ch, token)
    app_id = ensure_app(ch, token, tenant_id)
    dp_id = ensure_device_profile(ch, token, tenant_id)
    ensure_gateway(ch, token, tenant_id)

    out = []
    for name, tenant in DEVICES:
        rec = create_device(ch, token, app_id, dp_id, name)
        rec["tenant"] = tenant
        rec["attacker"] = name.startswith("attacker")
        out.append(rec)
        print("provisioned %-22s tenant=%-11s devaddr=%08x" % (name, tenant, rec["devaddr"]))

    path = os.path.join(os.path.dirname(__file__), "devices.json")
    with open(path, "w") as f:
        json.dump({"gateway_eui": GATEWAY_EUI, "devices": out}, f, indent=1)
    print("\nwrote %s (%d devices)" % (path, len(out)))


if __name__ == "__main__":
    main()
