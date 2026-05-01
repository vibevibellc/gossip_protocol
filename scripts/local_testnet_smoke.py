#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parent.parent
BINARY = REPO_ROOT / "target" / "debug" / "gossip_protocol"
EXPECTED_HEADER_NAME = "x-health-key"
EXPECTED_HEADER_VALUE = "smoke-secret"
EXPECTED_REGION = "us-west"
TOKEN = 1_000_000
CONTROL_API_TOKEN = "local-control-token"
GOSSIP_API_TOKEN = "local-gossip-token"
WALLET_PASSPHRASE_ENV = "GOSSIP_PROTOCOL_WALLET_PASSPHRASE"
WALLET_PASSPHRASE_VALUE = "local-test-wallet-passphrase"


@dataclass
class NodeSpec:
    name: str
    wallet: Path
    state_dir: Path
    bind: str
    peers: List[str]
    log_path: Path


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "gossip-protocol-smoke/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/health":
            self.send_error(404, "not found")
            return

        expected_header = self.headers.get(EXPECTED_HEADER_NAME)
        region = parse_qs(parsed.query).get("region", [None])[0]
        if expected_header != EXPECTED_HEADER_VALUE:
            self._send_json(
                403,
                {
                    "ready": False,
                    "error": "missing_or_invalid_header",
                },
            )
            return
        if region != EXPECTED_REGION:
            self._send_json(
                400,
                {
                    "ready": False,
                    "error": "missing_or_invalid_region",
                },
            )
            return

        self._send_json(
            200,
            {
                "ready": True,
                "service": {
                    "name": "smoke-health",
                    "version": "1.0.0",
                },
                "region": region,
            },
            extra_headers={"x-network": "smoke-net"},
        )

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, status: int, payload: dict, extra_headers: Dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def http_get_json(url: str) -> dict:
    with urlopen(url, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def http_post_json(url: str, payload: dict, bearer_token: str | None = None) -> dict:
    headers = {"content-type": "application/json"}
    if bearer_token is not None:
        headers["authorization"] = f"Bearer {bearer_token}"
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=4) as response:
        return json.loads(response.read().decode("utf-8"))


def test_env() -> Dict[str, str]:
    env = os.environ.copy()
    env[WALLET_PASSPHRASE_ENV] = WALLET_PASSPHRASE_VALUE
    return env


def run_cmd(
    args: List[str],
    cwd: Path,
    capture_json: bool = False,
    extra_env: Dict[str, str] | None = None,
) -> dict | str:
    env = test_env()
    if extra_env:
        env.update(extra_env)
    completed = subprocess.run(
        args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    if capture_json:
        return json.loads(completed.stdout)
    return completed.stdout.strip()


def wait_for_http(url: str, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() < deadline:
        try:
            http_get_json(url)
            return
        except (URLError, HTTPError, TimeoutError, ConnectionError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {url}: {last_error}")


def start_health_server() -> Tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def start_node_process(node: NodeSpec, genesis: Path, swap_config: Path | None) -> subprocess.Popen:
    args = [
        str(BINARY),
        "node",
        "run",
        "--wallet",
        str(node.wallet),
        "--genesis",
        str(genesis),
        "--state-dir",
        str(node.state_dir),
        "--bind",
        node.bind,
    ]
    for peer in node.peers:
        args.extend(["--peer", peer])
    if swap_config is not None:
        args.extend(["--swap-config", str(swap_config)])
    args.extend(["--control-api-token", CONTROL_API_TOKEN])
    args.extend(["--gossip-api-token", GOSSIP_API_TOKEN])
    args.extend(["--wallet-passphrase-env", WALLET_PASSPHRASE_ENV])

    log_file = node.log_path.open("w", encoding="utf-8")
    env = test_env()
    env.setdefault("RUST_LOG", "info,hyper=warn,reqwest=warn")
    return subprocess.Popen(
        args,
        cwd=REPO_ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
    )


def process_alive(process: subprocess.Popen) -> bool:
    return process.poll() is None


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def build_binary() -> None:
    subprocess.run(["cargo", "build"], cwd=REPO_ROOT, check=True)


def wallet_address(wallet_path: Path) -> str:
    return run_cmd([str(BINARY), "wallet", "address", str(wallet_path)], REPO_ROOT)


def create_wallet(wallet_path: Path) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "wallet",
            "create",
            str(wallet_path),
            "--passphrase-env",
            WALLET_PASSPHRASE_ENV,
        ],
        REPO_ROOT,
        capture_json=True,
    )


def create_genesis(
    out_path: Path,
    validator_wallets: List[Path],
    user_address: str,
    validator_addresses: List[str],
) -> dict:
    args = [
        str(BINARY),
        "genesis",
        "create",
        "--out",
        str(out_path),
    ]
    for wallet in validator_wallets:
        args.extend(["--validator-wallet", str(wallet)])
    args.extend(
        [
            "--treasury",
            validator_addresses[0],
            "--airdrop",
            f"{user_address}=5",
            "--min-receipts",
            "2",
            "--block-time-secs",
            "3",
            "--chain-id",
            "local-smoke-testnet",
        ]
    )
    return run_cmd(args, REPO_ROOT, capture_json=True)


def health_check_cli_args(node_url: str, wallet_path: Path, health_url: str) -> List[str]:
    return [
        str(BINARY),
        "tx",
        "health-check",
        "--wallet",
        str(wallet_path),
        "--node",
        node_url,
        "--url",
        health_url,
        "--method",
        "get",
        "--header",
        f"{EXPECTED_HEADER_NAME}:{EXPECTED_HEADER_VALUE}",
        "--query",
        f"region={EXPECTED_REGION}",
        "--timeout-ms",
        "3000",
        "--expect-status",
        "200",
        "--assert-json",
        "ready=true",
        "--assert-json-exists",
        "service.name",
        "--assert-header",
        "x-network=smoke-net",
        "--allow-http",
        "--allow-private-targets",
    ]


def submit_health_check(
    node_url: str,
    wallet_path: Path,
    health_url: str,
    api_token: str | None = CONTROL_API_TOKEN,
) -> dict:
    args = health_check_cli_args(node_url, wallet_path, health_url)
    args.extend(["--wallet-passphrase-env", WALLET_PASSPHRASE_ENV])
    if api_token is not None:
        args.extend(["--api-token", api_token])
    return run_cmd(args, REPO_ROOT, capture_json=True)


def expect_unauthorized_submit(node_url: str, wallet_path: Path, health_url: str) -> None:
    try:
        submit_health_check(node_url, wallet_path, health_url, api_token=None)
    except RuntimeError as error:
        if "401" not in str(error):
            raise RuntimeError(f"expected unauthorized submit, saw: {error}") from error
        return
    raise RuntimeError("unsigned control submission unexpectedly succeeded without an API token")


def expect_unauthorized_swap_quote(node_url: str, wallet_address_value: str) -> None:
    try:
        http_post_json(
            f"{node_url}/v1/control/swap/quote",
            {
                "wallet": wallet_address_value,
                "token_amount": 2 * TOKEN,
                "side": "buy",
                "settlement_asset": "usdc",
                "adapter": "fixed-usdc-demo",
            },
        )
    except HTTPError as error:
        if error.code != 401:
            raise RuntimeError(f"expected 401 from unauthorized swap quote, saw {error.code}") from error
        return
    raise RuntimeError("unauthorized swap quote unexpectedly succeeded without an API token")


def fetch_job_until_finalized(node_url: str, tx_hash: str, timeout_seconds: float) -> dict:
    deadline = time.time() + timeout_seconds
    last_payload = None
    while time.time() < deadline:
        payload = http_get_json(f"{node_url}/v1/control/jobs/{tx_hash}")
        last_payload = payload
        if payload.get("finalized"):
            return payload
        time.sleep(0.5)
    raise RuntimeError(f"job {tx_hash} did not finalize: {last_payload}")


def fetch_ledger(node_url: str) -> dict:
    return http_get_json(f"{node_url}/v1/control/ledger")


def fetch_status(node_url: str) -> dict:
    return http_get_json(f"{node_url}/v1/control/status")


def fetch_account(node_url: str, address: str) -> dict:
    return http_get_json(f"{node_url}/v1/control/account/{address}")


def wait_for_status_height(node_url: str, expected_height: int, timeout_seconds: float) -> dict:
    deadline = time.time() + timeout_seconds
    last_status = None
    while time.time() < deadline:
        status = fetch_status(node_url)
        last_status = status
        if status.get("height") >= expected_height:
            return status
        time.sleep(0.5)
    raise RuntimeError(
        f"node {node_url} did not reach height {expected_height}: {last_status}"
    )


def fetch_swap_quote(
    node_url: str,
    wallet_address_value: str,
    *,
    side: str = "buy",
    token_amount: int = 2 * TOKEN,
    ttl_secs: int = 300,
) -> dict:
    return http_post_json(
        f"{node_url}/v1/control/swap/quote",
        {
            "wallet": wallet_address_value,
            "token_amount": token_amount,
            "side": side,
            "settlement_asset": "usdc",
            "adapter": "fixed-usdc-demo",
            "ttl_secs": ttl_secs,
        },
        bearer_token=CONTROL_API_TOKEN,
    )


def fetch_swap_lock(node_url: str, quote_id: str) -> dict:
    return http_get_json(f"{node_url}/v1/control/swaps/{quote_id}")


def submit_swap_lock(node_url: str, wallet_path: Path, quote_file: Path) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "swap",
            "lock",
            "--wallet",
            str(wallet_path),
            "--wallet-passphrase-env",
            WALLET_PASSPHRASE_ENV,
            "--node",
            node_url,
            "--quote-file",
            str(quote_file),
            "--api-token",
            CONTROL_API_TOKEN,
        ],
        REPO_ROOT,
        capture_json=True,
    )


def submit_swap_cancel(node_url: str, wallet_path: Path, quote_id: str) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "swap",
            "cancel",
            "--wallet",
            str(wallet_path),
            "--wallet-passphrase-env",
            WALLET_PASSPHRASE_ENV,
            "--node",
            node_url,
            "--quote-id",
            quote_id,
            "--api-token",
            CONTROL_API_TOKEN,
        ],
        REPO_ROOT,
        capture_json=True,
    )


def wait_for_swap_lock_state(node_url: str, quote_id: str, pending: bool, timeout_seconds: float) -> dict:
    deadline = time.time() + timeout_seconds
    last_payload = None
    while time.time() < deadline:
        payload = fetch_swap_lock(node_url, quote_id)
        last_payload = payload
        if payload.get("pending") == pending:
            return payload
        time.sleep(0.5)
    raise RuntimeError(f"swap lock {quote_id} did not reach pending={pending}: {last_payload}")


def verify_convergence(node_urls: List[str]) -> List[dict]:
    ledgers = [fetch_ledger(url) for url in node_urls]
    normalized = [json.dumps(ledger, sort_keys=True) for ledger in ledgers]
    if len(set(normalized)) != 1:
        raise RuntimeError("ledger snapshots diverged across nodes")
    return ledgers


def print_summary(summary: dict) -> None:
    print(json.dumps(summary, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local multi-node gossip_protocol smoke testnet")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    build_binary()

    work_root = Path(tempfile.mkdtemp(prefix="gossip-protocol-smoke-"))
    processes: List[subprocess.Popen] = []
    server = None

    try:
        wallets_dir = work_root / "wallets"
        states_dir = work_root / "states"
        logs_dir = work_root / "logs"
        wallets_dir.mkdir()
        states_dir.mkdir()
        logs_dir.mkdir()

        validator_wallets = [wallets_dir / f"validator{i}.json" for i in range(1, 4)]
        user_wallet = wallets_dir / "user.json"

        for wallet in validator_wallets + [user_wallet]:
            create_wallet(wallet)

        validator_addresses = [wallet_address(wallet) for wallet in validator_wallets]
        user_address = wallet_address(user_wallet)

        genesis_path = work_root / "genesis.json"
        genesis = create_genesis(
            genesis_path,
            validator_wallets,
            user_address,
            validator_addresses,
        )

        swap_config = REPO_ROOT / "examples" / "swap_adapters.json"
        node_specs = [
            NodeSpec(
                name="node1",
                wallet=validator_wallets[0],
                state_dir=states_dir / "node1",
                bind="127.0.0.1:9401",
                peers=["http://127.0.0.1:9402", "http://127.0.0.1:9403"],
                log_path=logs_dir / "node1.log",
            ),
            NodeSpec(
                name="node2",
                wallet=validator_wallets[1],
                state_dir=states_dir / "node2",
                bind="127.0.0.1:9402",
                peers=["http://127.0.0.1:9401", "http://127.0.0.1:9403"],
                log_path=logs_dir / "node2.log",
            ),
            NodeSpec(
                name="node3",
                wallet=validator_wallets[2],
                state_dir=states_dir / "node3",
                bind="127.0.0.1:9403",
                peers=["http://127.0.0.1:9401", "http://127.0.0.1:9402"],
                log_path=logs_dir / "node3.log",
            ),
        ]

        server, health_port = start_health_server()
        health_url = f"http://127.0.0.1:{health_port}/health"

        for spec in node_specs:
            spec.state_dir.mkdir()
            processes.append(start_node_process(spec, genesis_path, swap_config))

        for process, spec in zip(processes, node_specs):
            if not process_alive(process):
                raise RuntimeError(f"{spec.name} exited early, see {spec.log_path}")

        node_urls = [f"http://{spec.bind}" for spec in node_specs]
        for url in node_urls:
            wait_for_http(f"{url}/v1/control/ledger", 15)

        expect_unauthorized_submit(node_urls[0], user_wallet, health_url)
        expect_unauthorized_swap_quote(node_urls[0], user_address)
        submitted_tx = submit_health_check(node_urls[0], user_wallet, health_url)
        tx_hash = submitted_tx["hash"]
        finalized = fetch_job_until_finalized(node_urls[0], tx_hash, 20)
        ledgers = verify_convergence(node_urls)
        statuses = [fetch_status(url) for url in node_urls]

        user_accounts = [fetch_account(url, user_address) for url in node_urls]
        validator_accounts = {
            address: [fetch_account(url, address) for url in node_urls]
            for address in validator_addresses
        }

        expected_user_balance = 4 * TOKEN
        if any(account["balance"] != expected_user_balance for account in user_accounts):
            raise RuntimeError(f"user balance mismatch: {user_accounts}")

        receipt_count = len(finalized["finalized_record"]["receipts"])
        if receipt_count < 2:
            raise RuntimeError(f"expected at least 2 receipts, saw {receipt_count}")

        validator_balances = [
            validator_accounts[address][0]["balance"] for address in validator_addresses
        ]
        if sum(validator_balances) != TOKEN:
            raise RuntimeError(f"validator rewards did not sum to 1 HT: {validator_balances}")
        if any(status["validator_count"] != 3 for status in statuses):
            raise RuntimeError(f"unexpected validator_count in status responses: {statuses}")
        if any(status["height"] != ledgers[0]["height"] for status in statuses):
            raise RuntimeError(f"status endpoint height mismatch: {statuses}")
        if any(status["mempool_size"] != 0 for status in statuses):
            raise RuntimeError(f"expected empty mempool after finalization: {statuses}")

        swap_quote = fetch_swap_quote(node_urls[0], user_address)
        quoted_settlement_amount = swap_quote["quote"]["settlement_amount"]
        if quoted_settlement_amount != 2 * TOKEN:
            raise RuntimeError(
                f"swap quote settlement amount mismatch: expected {2 * TOKEN}, saw {quoted_settlement_amount}"
            )

        sell_quote = fetch_swap_quote(
            node_urls[0],
            user_address,
            side="sell",
            token_amount=2 * TOKEN,
            ttl_secs=6,
        )
        sell_quote_id = sell_quote["quote"]["quote_id"]
        sell_quote_file = work_root / "sell_quote.json"
        sell_quote_file.write_text(json.dumps(sell_quote, indent=2), encoding="utf-8")
        submit_swap_lock(node_urls[0], user_wallet, sell_quote_file)
        pending_swap = wait_for_swap_lock_state(node_urls[0], sell_quote_id, True, 15)
        locked_account = fetch_account(node_urls[0], user_address)
        if locked_account["locked_balance"] != 2 * TOKEN:
            raise RuntimeError(f"expected 2 HT locked during swap hold, saw {locked_account}")

        time.sleep(6.5)
        submit_swap_cancel(node_urls[0], user_wallet, sell_quote_id)
        cleared_swap = wait_for_swap_lock_state(node_urls[0], sell_quote_id, False, 15)
        unlocked_account = fetch_account(node_urls[0], user_address)
        if unlocked_account["locked_balance"] != 0:
            raise RuntimeError(f"expected swap lock to clear after cancel: {unlocked_account}")
        if unlocked_account["balance"] != expected_user_balance:
            raise RuntimeError(f"unexpected balance after swap cancel: {unlocked_account}")

        pre_liveness_status = fetch_status(node_urls[0])
        stop_process(processes[1])
        time.sleep(0.5)
        if process_alive(processes[1]):
            raise RuntimeError(f"{node_specs[1].name} failed to stop for liveness testing")

        liveness_submitted_tx = submit_health_check(node_urls[0], user_wallet, health_url)
        liveness_tx_hash = liveness_submitted_tx["hash"]
        liveness_finalized = fetch_job_until_finalized(node_urls[0], liveness_tx_hash, 20)
        surviving_node_urls = [node_urls[0], node_urls[2]]
        surviving_ledgers = verify_convergence(surviving_node_urls)
        surviving_statuses = [fetch_status(url) for url in surviving_node_urls]
        surviving_user_accounts = [fetch_account(url, user_address) for url in surviving_node_urls]

        expected_post_liveness_balance = 3 * TOKEN
        if any(account["balance"] != expected_post_liveness_balance for account in surviving_user_accounts):
            raise RuntimeError(
                f"user balance mismatch after offline-proposer liveness test: {surviving_user_accounts}"
            )
        expected_liveness_height = pre_liveness_status["height"] + 1
        if any(status["height"] != expected_liveness_height for status in surviving_statuses):
            raise RuntimeError(
                "expected surviving nodes to finalize exactly one new block after "
                f"offline-proposer recovery: {surviving_statuses}"
            )
        if any(status["mempool_size"] != 0 for status in surviving_statuses):
            raise RuntimeError(
                f"expected surviving mempools to drain after offline-proposer recovery: {surviving_statuses}"
            )
        if len(liveness_finalized["finalized_record"]["receipts"]) < 2:
            raise RuntimeError(
                f"expected at least 2 receipts in offline-proposer recovery block: {liveness_finalized}"
            )

        processes[1] = start_node_process(node_specs[1], genesis_path, swap_config)
        if not process_alive(processes[1]):
            raise RuntimeError(f"{node_specs[1].name} failed to restart for catch-up testing")
        wait_for_http(f"{node_urls[1]}/v1/control/ledger", 15)
        restarted_status = wait_for_status_height(
            node_urls[1],
            expected_liveness_height,
            20,
        )
        converged_after_restart = verify_convergence(node_urls)
        restarted_account = fetch_account(node_urls[1], user_address)
        if restarted_account["balance"] != expected_post_liveness_balance:
            raise RuntimeError(
                f"restarted node did not catch up user balance correctly: {restarted_account}"
            )
        state_snapshot_path = node_specs[0].state_dir / "state.json"
        state_snapshot = json.loads(state_snapshot_path.read_text(encoding="utf-8"))
        if "finalized_blocks" in state_snapshot:
            raise RuntimeError("hot state snapshot still contains finalized_blocks")
        if "finalized_health_checks" in state_snapshot.get("chain", {}):
            raise RuntimeError("hot state snapshot still contains finalized_health_checks")
        block_archive_path = (
            node_specs[0].state_dir
            / "blocks"
            / f"{expected_liveness_height:020}.json"
        )
        if not block_archive_path.exists():
            raise RuntimeError(f"missing archived finalized block: {block_archive_path}")
        health_archive_path = (
            node_specs[0].state_dir
            / "health_checks"
            / f"{liveness_tx_hash}.json"
        )
        if not health_archive_path.exists():
            raise RuntimeError(
                f"missing archived finalized health record: {health_archive_path}"
            )
        journal_path = node_specs[0].state_dir / "state.wal"
        if not journal_path.exists():
            raise RuntimeError(f"missing journal file after compaction: {journal_path}")
        if journal_path.read_text(encoding="utf-8").strip():
            raise RuntimeError(f"expected compacted journal to be empty: {journal_path}")

        summary = {
            "work_root": str(work_root),
            "chain_id": genesis["chain_id"],
            "health_url": health_url,
            "submitted_tx_hash": tx_hash,
            "finalized_height": ledgers[0]["height"],
            "finalized_block_hash": ledgers[0]["last_block_hash"],
            "receipt_count": receipt_count,
            "user_balance_micro_ht": user_accounts[0]["balance"],
            "validator_balances_micro_ht": {
                validator_addresses[index]: validator_balances[index]
                for index in range(len(validator_addresses))
            },
            "swap_quote": swap_quote,
            "sell_quote_id": sell_quote_id,
            "pending_swap_record": pending_swap,
            "cleared_swap_record": cleared_swap,
            "job_record": finalized["finalized_record"],
            "offline_proposer_liveness": {
                "stopped_node": node_specs[1].name,
                "stopped_validator": validator_addresses[1],
                "submitted_tx_hash": liveness_tx_hash,
                "finalized_height": surviving_ledgers[0]["height"],
                "job_record": liveness_finalized["finalized_record"],
                "surviving_node_urls": surviving_node_urls,
                "surviving_statuses": surviving_statuses,
                "user_balance_micro_ht": surviving_user_accounts[0]["balance"],
            },
            "restart_catch_up": {
                "restarted_node": node_specs[1].name,
                "restarted_status": restarted_status,
                "converged_height": converged_after_restart[0]["height"],
                "user_balance_micro_ht": restarted_account["balance"],
            },
            "storage_split": {
                "state_snapshot_path": str(state_snapshot_path),
                "archived_block_path": str(block_archive_path),
                "archived_health_record_path": str(health_archive_path),
                "journal_path": str(journal_path),
            },
            "node_urls": node_urls,
            "statuses": statuses,
            "logs": {spec.name: str(spec.log_path) for spec in node_specs},
        }
        print_summary(summary)

        if not args.keep_artifacts:
            shutil.rmtree(work_root)
        return 0
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        for process in processes:
            stop_process(process)
        if args.keep_artifacts and work_root.exists():
            print(f"kept artifacts in {work_root}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
