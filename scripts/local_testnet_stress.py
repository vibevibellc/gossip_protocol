#!/usr/bin/env python3

import argparse
import concurrent.futures
import json
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import local_testnet_smoke as base


VALIDATOR_COUNT = 5
USER_COUNT = 5
WAVE_COUNT = 4
BLOCK_TIME_SECONDS = 2
MIN_RECEIPTS = 3
REQUEST_HEADER_NAME = base.EXPECTED_HEADER_NAME
REQUEST_HEADER_VALUE = base.EXPECTED_HEADER_VALUE
REQUEST_REGION = base.EXPECTED_REGION


@dataclass
class Scenario:
    name: str
    method: str
    path: str
    expected_success: bool
    expected_status: int
    supplied_headers: Dict[str, str]
    query: Dict[str, str]
    timeout_ms: int
    assert_json: List[str]
    assert_json_exists: List[str]
    assert_header: List[str]
    assert_body_contains: List[str]
    body_json: str | None = None
    expected_receipt_status: int | None = None
    expect_error: bool = False


class StressHealthHandler(BaseHTTPRequestHandler):
    server_version = "gossip-protocol-stress/1.0"

    def do_GET(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch(head_only=True)

    def do_POST(self) -> None:
        self._dispatch()

    def log_message(self, format: str, *args) -> None:
        return

    def _dispatch(self, head_only: bool = False) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health/ok":
            self._handle_ok(parsed, head_only=head_only)
            return
        if parsed.path == "/health/head":
            self._handle_head(parsed, head_only=head_only)
            return
        if parsed.path == "/health/post":
            self._handle_post(parsed, head_only=head_only)
            return
        if parsed.path == "/health/degraded":
            self._handle_degraded(parsed, head_only=head_only)
            return
        if parsed.path == "/health/slow":
            self._handle_slow(parsed, head_only=head_only)
            return
        self.send_error(404, "not found")

    def _header_ok(self) -> bool:
        return self.headers.get(REQUEST_HEADER_NAME) == REQUEST_HEADER_VALUE

    def _region_ok(self, parsed) -> bool:
        return parse_qs(parsed.query).get("region", [None])[0] == REQUEST_REGION

    def _json_response(
        self,
        status: int,
        payload: dict,
        *,
        extra_headers: Dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if head_only:
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _handle_ok(self, parsed, *, head_only: bool) -> None:
        if not self._header_ok():
            self._json_response(
                403,
                {"ready": False, "error": "missing_or_invalid_header"},
                extra_headers={"x-network": "stress-net"},
                head_only=head_only,
            )
            return
        if not self._region_ok(parsed):
            self._json_response(
                400,
                {"ready": False, "error": "missing_or_invalid_region"},
                extra_headers={"x-network": "stress-net"},
                head_only=head_only,
            )
            return
        self._json_response(
            200,
            {
                "ready": True,
                "service": {
                    "name": "stress-health",
                    "version": "2.0.0",
                },
                "region": REQUEST_REGION,
                "kind": "ok",
            },
            extra_headers={"x-network": "stress-net", "x-health-mode": "ok"},
            head_only=head_only,
        )

    def _handle_head(self, parsed, *, head_only: bool) -> None:
        if not self._header_ok() or not self._region_ok(parsed):
            self._json_response(
                403,
                {"ready": False},
                extra_headers={"x-health-mode": "head"},
                head_only=head_only,
            )
            return
        self._json_response(
            200,
            {"ready": True, "kind": "head"},
            extra_headers={"x-health-mode": "head", "x-network": "stress-net"},
            head_only=head_only,
        )

    def _handle_post(self, parsed, *, head_only: bool) -> None:
        if not self._header_ok() or not self._region_ok(parsed):
            self._json_response(
                403,
                {"accepted": False, "error": "forbidden"},
                extra_headers={"x-network": "stress-net"},
                head_only=head_only,
            )
            return

        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        payload = json.loads(raw.decode("utf-8"))
        self._json_response(
            200,
            {
                "accepted": True,
                "echo": payload,
                "kind": "post",
            },
            extra_headers={"x-network": "stress-net", "x-health-mode": "post"},
            head_only=head_only,
        )

    def _handle_degraded(self, parsed, *, head_only: bool) -> None:
        if not self._header_ok() or not self._region_ok(parsed):
            self._json_response(
                403,
                {"ready": False, "error": "forbidden"},
                extra_headers={"x-network": "stress-net"},
                head_only=head_only,
            )
            return

        self._json_response(
            503,
            {
                "ready": False,
                "service": {
                    "name": "stress-health",
                    "version": "2.0.0",
                },
                "kind": "degraded",
            },
            extra_headers={"x-network": "stress-net", "retry-after": "1"},
            head_only=head_only,
        )

    def _handle_slow(self, parsed, *, head_only: bool) -> None:
        delay_ms = int(parse_qs(parsed.query).get("delay_ms", ["500"])[0])
        time.sleep(delay_ms / 1000.0)
        self._json_response(
            200,
            {"ready": True, "delay_ms": delay_ms, "kind": "slow"},
            extra_headers={"x-network": "stress-net"},
            head_only=head_only,
        )


def start_health_server() -> Tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), StressHealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def create_genesis(
    out_path: Path,
    validator_wallets: List[Path],
    validator_addresses: List[str],
    user_addresses: List[str],
    total_waves: int,
) -> dict:
    args = [
        str(base.BINARY),
        "genesis",
        "create",
        "--out",
        str(out_path),
        "--treasury",
        validator_addresses[0],
        "--min-receipts",
        str(MIN_RECEIPTS),
        "--block-time-secs",
        str(BLOCK_TIME_SECONDS),
        "--chain-id",
        "local-stress-testnet",
    ]
    for wallet in validator_wallets:
        args.extend(["--validator-wallet", str(wallet)])
    for address in user_addresses:
        args.extend(["--airdrop", f"{address}={total_waves}"])
    return base.run_cmd(args, base.REPO_ROOT, capture_json=True)


def build_scenarios(base_url: str) -> List[List[Scenario]]:
    def ok_headers() -> Dict[str, str]:
        return {REQUEST_HEADER_NAME: REQUEST_HEADER_VALUE}

    def ok_query() -> Dict[str, str]:
        return {"region": REQUEST_REGION}

    return [
        [
            Scenario(
                name="ok-get-body",
                method="get",
                path="/health/ok",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=["service.version"],
                assert_header=["x-network=stress-net"],
                assert_body_contains=["stress-health"],
            ),
            Scenario(
                name="head-ok",
                method="head",
                path="/health/head",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1000,
                assert_json=[],
                assert_json_exists=[],
                assert_header=["x-health-mode=head"],
                assert_body_contains=[],
            ),
            Scenario(
                name="post-ok",
                method="post",
                path="/health/post",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["accepted=true", 'echo.mode="stress"', "echo.ticket=1"],
                assert_json_exists=[],
                assert_header=["x-health-mode=post"],
                assert_body_contains=[],
                body_json=json.dumps({"mode": "stress", "ticket": 1}),
            ),
            Scenario(
                name="degraded-status",
                method="get",
                path="/health/degraded",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=503,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=[],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="timeout",
                method="get",
                path="/health/slow",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=None,
                supplied_headers=ok_headers(),
                query={"region": REQUEST_REGION, "delay_ms": "400"},
                timeout_ms=100,
                assert_json=[],
                assert_json_exists=[],
                assert_header=[],
                assert_body_contains=[],
                expect_error=True,
            ),
        ],
        [
            Scenario(
                name="ok-get-json",
                method="get",
                path="/health/ok",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true", 'service.name="stress-health"'],
                assert_json_exists=[],
                assert_header=["x-health-mode=ok"],
                assert_body_contains=[],
            ),
            Scenario(
                name="bad-header",
                method="get",
                path="/health/ok",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=403,
                supplied_headers={REQUEST_HEADER_NAME: "wrong-secret"},
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=[],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="post-ok-2",
                method="post",
                path="/health/post",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["accepted=true", "echo.ticket=2"],
                assert_json_exists=["echo.mode"],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
                body_json=json.dumps({"mode": "stress", "ticket": 2}),
            ),
            Scenario(
                name="assertion-fail",
                method="get",
                path="/health/ok",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=false"],
                assert_json_exists=[],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="head-ok-2",
                method="head",
                path="/health/head",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1000,
                assert_json=[],
                assert_json_exists=[],
                assert_header=["x-network=stress-net", "x-health-mode=head"],
                assert_body_contains=[],
            ),
        ],
        [
            Scenario(
                name="post-ok-3",
                method="post",
                path="/health/post",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["accepted=true", "echo.ticket=3"],
                assert_json_exists=[],
                assert_header=["x-health-mode=post"],
                assert_body_contains=[],
                body_json=json.dumps({"mode": "stress", "ticket": 3}),
            ),
            Scenario(
                name="degraded-2",
                method="get",
                path="/health/degraded",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=503,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=[],
                assert_json_exists=["service.version"],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="ok-get-body-2",
                method="get",
                path="/health/ok",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=[],
                assert_header=["x-network=stress-net"],
                assert_body_contains=["\"kind\": \"ok\""],
            ),
            Scenario(
                name="timeout-2",
                method="get",
                path="/health/slow",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=None,
                supplied_headers=ok_headers(),
                query={"region": REQUEST_REGION, "delay_ms": "500"},
                timeout_ms=100,
                assert_json=[],
                assert_json_exists=[],
                assert_header=[],
                assert_body_contains=[],
                expect_error=True,
            ),
            Scenario(
                name="head-ok-3",
                method="head",
                path="/health/head",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1000,
                assert_json=[],
                assert_json_exists=[],
                assert_header=["x-health-mode=head"],
                assert_body_contains=[],
            ),
        ],
        [
            Scenario(
                name="ok-get-final",
                method="get",
                path="/health/ok",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=["service.name"],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="post-ok-final",
                method="post",
                path="/health/post",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["accepted=true", "echo.ticket=4"],
                assert_json_exists=["echo.mode"],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
                body_json=json.dumps({"mode": "stress", "ticket": 4}),
            ),
            Scenario(
                name="bad-header-final",
                method="get",
                path="/health/ok",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=403,
                supplied_headers={REQUEST_HEADER_NAME: "bad-final"},
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=[],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="assertion-fail-final",
                method="get",
                path="/health/ok",
                expected_success=False,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1500,
                assert_json=["ready=true"],
                assert_json_exists=[],
                assert_header=["x-network=wrong-net"],
                assert_body_contains=[],
            ),
            Scenario(
                name="ok-head-final",
                method="head",
                path="/health/head",
                expected_success=True,
                expected_status=200,
                expected_receipt_status=200,
                supplied_headers=ok_headers(),
                query=ok_query(),
                timeout_ms=1000,
                assert_json=[],
                assert_json_exists=[],
                assert_header=["x-network=stress-net"],
                assert_body_contains=[],
            ),
        ],
    ]


def submit_scenario(node_url: str, wallet_path: Path, url: str, scenario: Scenario) -> dict:
    args = [
        str(base.BINARY),
        "tx",
        "health-check",
        "--wallet",
        str(wallet_path),
        "--wallet-passphrase-env",
        base.WALLET_PASSPHRASE_ENV,
        "--node",
        node_url,
        "--api-token",
        base.CONTROL_API_TOKEN,
        "--url",
        url,
        "--method",
        scenario.method,
        "--timeout-ms",
        str(scenario.timeout_ms),
        "--expect-status",
        str(scenario.expected_status),
        "--allow-http",
        "--allow-private-targets",
    ]
    for key, value in scenario.supplied_headers.items():
        args.extend(["--header", f"{key}:{value}"])
    for key, value in scenario.query.items():
        args.extend(["--query", f"{key}={value}"])
    for item in scenario.assert_json:
        args.extend(["--assert-json", item])
    for item in scenario.assert_json_exists:
        args.extend(["--assert-json-exists", item])
    for item in scenario.assert_header:
        args.extend(["--assert-header", item])
    for item in scenario.assert_body_contains:
        args.extend(["--assert-body-contains", item])
    if scenario.body_json is not None:
        args.extend(["--body-json", scenario.body_json])
    return base.run_cmd(args, base.REPO_ROOT, capture_json=True)


def verify_record(record: dict, scenario: Scenario, validator_count: int) -> None:
    expected_success_count = validator_count if scenario.expected_success else 0
    expected_failure_count = 0 if scenario.expected_success else validator_count

    if record["success_count"] != expected_success_count:
        raise RuntimeError(
            f"{scenario.name} success_count mismatch: expected {expected_success_count}, "
            f"saw {record['success_count']}"
        )
    if record["failure_count"] != expected_failure_count:
        raise RuntimeError(
            f"{scenario.name} failure_count mismatch: expected {expected_failure_count}, "
            f"saw {record['failure_count']}"
        )
    if len(record["receipts"]) != validator_count:
        raise RuntimeError(
            f"{scenario.name} receipt count mismatch: expected {validator_count}, "
            f"saw {len(record['receipts'])}"
        )

    for receipt in record["receipts"]:
        body = receipt["body"]
        if body["success"] != scenario.expected_success:
            raise RuntimeError(
                f"{scenario.name} receipt success mismatch for {body['executor']}: "
                f"expected {scenario.expected_success}, saw {body['success']}"
            )
        if body["response_status"] != scenario.expected_receipt_status:
            raise RuntimeError(
                f"{scenario.name} response status mismatch: expected {scenario.expected_receipt_status}, "
                f"saw {body['response_status']}"
            )
        if scenario.expect_error and not body["error"]:
            raise RuntimeError(f"{scenario.name} expected an error but receipt had none")
        if not scenario.expect_error and body["error"] is not None:
            raise RuntimeError(f"{scenario.name} expected no error but saw {body['error']}")
        if scenario.method == "head" and body["response_body_sample"] is not None:
            raise RuntimeError(f"{scenario.name} expected HEAD receipts to have no body sample")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a stressed local multi-node gossip_protocol testnet")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--cycles", type=int, default=1)
    args = parser.parse_args()
    if args.cycles < 1:
        raise SystemExit("--cycles must be at least 1")

    base.build_binary()

    work_root = Path(tempfile.mkdtemp(prefix="gossip-protocol-stress-"))
    processes = []
    health_server = None

    try:
        wallets_dir = work_root / "wallets"
        states_dir = work_root / "states"
        logs_dir = work_root / "logs"
        wallets_dir.mkdir()
        states_dir.mkdir()
        logs_dir.mkdir()

        validator_wallets = [wallets_dir / f"validator{i}.json" for i in range(1, VALIDATOR_COUNT + 1)]
        user_wallets = [wallets_dir / f"user{i}.json" for i in range(1, USER_COUNT + 1)]

        for wallet in validator_wallets + user_wallets:
            base.create_wallet(wallet)

        validator_addresses = [base.wallet_address(wallet) for wallet in validator_wallets]
        user_addresses = [base.wallet_address(wallet) for wallet in user_wallets]
        genesis_path = work_root / "genesis.json"
        total_waves = WAVE_COUNT * args.cycles
        genesis = create_genesis(
            genesis_path,
            validator_wallets,
            validator_addresses,
            user_addresses,
            total_waves,
        )

        swap_config = base.REPO_ROOT / "examples" / "swap_adapters.json"
        node_specs = []
        for index, wallet in enumerate(validator_wallets, start=1):
            bind_port = 9500 + index
            peers = [
                f"http://127.0.0.1:{9500 + peer_index}"
                for peer_index in range(1, VALIDATOR_COUNT + 1)
                if peer_index != index
            ]
            spec = base.NodeSpec(
                name=f"node{index}",
                wallet=wallet,
                state_dir=states_dir / f"node{index}",
                bind=f"127.0.0.1:{bind_port}",
                peers=peers,
                log_path=logs_dir / f"node{index}.log",
            )
            spec.state_dir.mkdir()
            node_specs.append(spec)
            processes.append(base.start_node_process(spec, genesis_path, swap_config))

        for process, spec in zip(processes, node_specs):
            if not base.process_alive(process):
                raise RuntimeError(f"{spec.name} exited early, see {spec.log_path}")

        node_urls = [f"http://{spec.bind}" for spec in node_specs]
        for url in node_urls:
            base.wait_for_http(f"{url}/v1/control/ledger", 20)

        health_server, health_port = start_health_server()
        scenarios_by_wave = build_scenarios(f"http://127.0.0.1:{health_port}")
        if len(scenarios_by_wave) != WAVE_COUNT:
            raise RuntimeError("scenario wave count does not match configured wave count")

        job_results = []
        start_time = time.time()
        for cycle_index in range(1, args.cycles + 1):
            for wave_offset, scenarios in enumerate(scenarios_by_wave, start=1):
                wave_index = ((cycle_index - 1) * WAVE_COUNT) + wave_offset
                submitted = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=USER_COUNT) as executor:
                    futures = []
                    for user_index, scenario in enumerate(scenarios):
                        wallet = user_wallets[user_index]
                        node_url = node_urls[(wave_index + user_index) % len(node_urls)]
                        request_url = f"http://127.0.0.1:{health_port}{scenario.path}"
                        futures.append(
                            executor.submit(submit_scenario, node_url, wallet, request_url, scenario)
                        )
                    for user_index, future in enumerate(futures):
                        tx = future.result()
                        submitted.append(
                            {
                                "user_wallet": str(user_wallets[user_index]),
                                "user_address": user_addresses[user_index],
                                "scenario": scenarios[user_index],
                                "tx": tx,
                            }
                        )

                for item in submitted:
                    tx_hash = item["tx"]["hash"]
                    job = base.fetch_job_until_finalized(node_urls[0], tx_hash, 30)
                    record = job["finalized_record"]
                    verify_record(record, item["scenario"], VALIDATOR_COUNT)
                    job_results.append(
                        {
                            "cycle": cycle_index,
                            "wave": wave_index,
                            "user_address": item["user_address"],
                            "scenario": item["scenario"].name,
                            "tx_hash": tx_hash,
                            "success_count": record["success_count"],
                            "failure_count": record["failure_count"],
                            "requester_cost": record["requester_cost"],
                        }
                    )

                base.verify_convergence(node_urls)
                time.sleep(BLOCK_TIME_SECONDS + 0.25)

        ledgers = base.verify_convergence(node_urls)
        final_height = ledgers[0]["height"]
        if final_height < total_waves:
            raise RuntimeError(f"expected at least {total_waves} blocks, saw height {final_height}")
        statuses = [base.fetch_status(url) for url in node_urls]
        if any(status["validator_count"] != VALIDATOR_COUNT for status in statuses):
            raise RuntimeError(f"unexpected validator count from status endpoint: {statuses}")
        if any(status["height"] != final_height for status in statuses):
            raise RuntimeError(f"status endpoint height mismatch after stress run: {statuses}")
        if any(status["mempool_size"] != 0 for status in statuses):
            raise RuntimeError(f"expected empty mempool after stress run: {statuses}")

        for address in user_addresses:
            accounts = [base.fetch_account(url, address) for url in node_urls]
            if any(account["balance"] != 0 for account in accounts):
                raise RuntimeError(f"user {address} balance mismatch after spend-down: {accounts}")

        validator_balance_map = {}
        expected_validator_balance = (USER_COUNT * total_waves * base.TOKEN) // VALIDATOR_COUNT
        for address in validator_addresses:
            accounts = [base.fetch_account(url, address) for url in node_urls]
            if any(account["balance"] != expected_validator_balance for account in accounts):
                raise RuntimeError(
                    f"validator {address} reward mismatch: expected {expected_validator_balance}, saw {accounts}"
                )
            validator_balance_map[address] = accounts[0]["balance"]

        swap_quote = base.fetch_swap_quote(node_urls[0], user_addresses[0])
        if swap_quote["quote"]["settlement_amount"] != 2 * base.TOKEN:
            raise RuntimeError("swap quote math regressed under stress")

        elapsed_ms = int((time.time() - start_time) * 1000)
        success_jobs = sum(1 for result in job_results if result["success_count"] == VALIDATOR_COUNT)
        failed_jobs = len(job_results) - success_jobs

        summary = {
            "work_root": str(work_root),
            "chain_id": genesis["chain_id"],
            "validator_count": VALIDATOR_COUNT,
            "user_count": USER_COUNT,
            "wave_count": total_waves,
            "cycles": args.cycles,
            "jobs_submitted": len(job_results),
            "success_jobs": success_jobs,
            "failed_jobs": failed_jobs,
            "final_height": final_height,
            "elapsed_ms": elapsed_ms,
            "validator_balances_micro_ht": validator_balance_map,
            "job_results": job_results,
            "swap_quote": swap_quote,
            "node_urls": node_urls,
            "statuses": statuses,
            "logs": {spec.name: str(spec.log_path) for spec in node_specs},
        }
        print(json.dumps(summary, indent=2, sort_keys=True))

        if not args.keep_artifacts:
            shutil.rmtree(work_root)
        return 0
    finally:
        if health_server is not None:
            health_server.shutdown()
            health_server.server_close()
        for process in processes:
            base.stop_process(process)
        if args.keep_artifacts and work_root.exists():
            print(f"kept artifacts in {work_root}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
