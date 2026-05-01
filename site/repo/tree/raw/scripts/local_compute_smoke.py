#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parent.parent
BINARY = REPO_ROOT / "target" / "debug" / "gossip_protocol"
TOKEN = 1_000_000
CONTROL_API_TOKEN = "local-control-token"
GOSSIP_API_TOKEN = "local-gossip-token"
AGENT_API_TOKEN = "local-agent-token"
WALLET_PASSPHRASE_ENV = "GOSSIP_PROTOCOL_WALLET_PASSPHRASE"
WALLET_PASSPHRASE_VALUE = "local-test-wallet-passphrase"
EMPTY_WASI_START_HEX = (
    "0061736d01000000"
    "010401600000"
    "03020100"
    "070a01065f73746172740000"
    "0a040102000b"
)


@dataclass
class NodeSpec:
    name: str
    wallet: Path
    state_dir: Path
    bind: str
    peers: List[str]
    log_path: Path


@dataclass
class AgentSpec:
    name: str
    wallet: Path
    bind: str
    log_path: Path


@dataclass
class StorageHostSpec:
    bind: str
    store_dir: Path
    log_path: Path


def test_env() -> Dict[str, str]:
    env = os.environ.copy()
    env[WALLET_PASSPHRASE_ENV] = WALLET_PASSPHRASE_VALUE
    env.setdefault("RUST_LOG", "info,hyper=warn,reqwest=warn")
    return env


def run_cmd(args: List[str], capture_json: bool = False) -> dict | str:
    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=test_env(),
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


def http_get_json(url: str) -> dict:
    with urlopen(url, timeout=3) as response:
        return json.loads(response.read().decode("utf-8"))


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


def build_binary() -> None:
    subprocess.run(["cargo", "build"], cwd=REPO_ROOT, check=True)


def create_wallet(path: Path) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "wallet",
            "create",
            str(path),
            "--passphrase-env",
            WALLET_PASSPHRASE_ENV,
        ],
        capture_json=True,
    )


def wallet_address(path: Path) -> str:
    return run_cmd([str(BINARY), "wallet", "address", str(path)])


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
            f"{user_address}=20",
            "--storage-airdrop",
            f"{user_address}=10",
            "--compute-airdrop",
            f"{user_address}=20",
            "--min-receipts",
            "2",
            "--block-time-secs",
            "3",
            "--chain-id",
            "local-compute-smoke",
        ]
    )
    return run_cmd(args, capture_json=True)


def start_node_process(node: NodeSpec, genesis: Path, probe_agents: Path) -> subprocess.Popen:
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
        "--probe-agents",
        str(probe_agents),
        "--control-api-token",
        CONTROL_API_TOKEN,
        "--gossip-api-token",
        GOSSIP_API_TOKEN,
        "--wallet-passphrase-env",
        WALLET_PASSPHRASE_ENV,
    ]
    for peer in node.peers:
        args.extend(["--peer", peer])
    log_file = node.log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        args,
        cwd=REPO_ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=test_env(),
    )


def start_agent_process(agent: AgentSpec) -> subprocess.Popen:
    args = [
        str(BINARY),
        "agent",
        "run",
        "--wallet",
        str(agent.wallet),
        "--bind",
        agent.bind,
        "--api-token",
        AGENT_API_TOKEN,
        "--wallet-passphrase-env",
        WALLET_PASSPHRASE_ENV,
    ]
    log_file = agent.log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        args,
        cwd=REPO_ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=test_env(),
    )


def start_storage_host_process(host: StorageHostSpec) -> subprocess.Popen:
    args = [
        str(BINARY),
        "storage",
        "host",
        "--store-dir",
        str(host.store_dir),
        "--bind",
        host.bind,
    ]
    log_file = host.log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        args,
        cwd=REPO_ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=test_env(),
    )


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


def fetch_job_until_finalized(node_url: str, tx_hash: str, timeout_seconds: float) -> dict:
    deadline = time.time() + timeout_seconds
    last_payload = None
    while time.time() < deadline:
        payload = http_get_json(f"{node_url}/v1/control/jobs/{tx_hash}")
        last_payload = payload
        if payload.get("finalized"):
            return payload
        time.sleep(0.5)
    raise RuntimeError(f"compute job {tx_hash} did not finalize: {last_payload}")


def submit_compute_job(node_url: str, wallet: Path, spec_file: Path) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "tx",
            "compute-job",
            "--wallet",
            str(wallet),
            "--wallet-passphrase-env",
            WALLET_PASSPHRASE_ENV,
            "--node",
            node_url,
            "--spec-file",
            str(spec_file),
            "--api-token",
            CONTROL_API_TOKEN,
        ],
        capture_json=True,
    )


def submit_storage_create(node_url: str, wallet: Path, spec_file: Path) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "tx",
            "storage-create",
            "--wallet",
            str(wallet),
            "--wallet-passphrase-env",
            WALLET_PASSPHRASE_ENV,
            "--node",
            node_url,
            "--spec-file",
            str(spec_file),
            "--prepaid-balance",
            "1",
            "--api-token",
            CONTROL_API_TOKEN,
        ],
        capture_json=True,
    )


def fetch_storage_contract_until_active(
    node_url: str, contract_id: str, timeout_seconds: float
) -> dict:
    deadline = time.time() + timeout_seconds
    last_payload = None
    while time.time() < deadline:
        try:
            payload = http_get_json(f"{node_url}/v1/control/storage/{contract_id}")
            last_payload = payload
            contract = payload.get("contract", {})
            if contract.get("status") == "active":
                return payload
        except (URLError, HTTPError, TimeoutError, ConnectionError, json.JSONDecodeError) as error:
            last_payload = {"error": str(error)}
        time.sleep(0.5)
    raise RuntimeError(f"storage contract {contract_id} did not activate: {last_payload}")


def build_wasi_module_bundle(
    work_root: Path, storage_store_dir: Path, host_address: str
) -> tuple[dict, Path]:
    module_dir = work_root / "module"
    module_dir.mkdir()
    module_path = module_dir / "job.wasm"
    module_path.write_bytes(bytes.fromhex(EMPTY_WASI_START_HEX))
    bundle = run_cmd(
        [
            str(BINARY),
            "storage",
            "bundle",
            "--input",
            str(module_path),
            "--out-dir",
            str(storage_store_dir),
            "--host",
            host_address,
            "--mode",
            "public-raw",
            "--chunk-size-bytes",
            "1024",
            "--duration-secs",
            "3600",
            "--proof-interval-secs",
            "60",
            "--proof-sample-count",
            "1",
        ],
        capture_json=True,
    )
    return bundle, module_path


def build_compute_module_ref(bundle: dict, host_url: str, module_path: Path) -> dict:
    return run_cmd(
        [
            str(BINARY),
            "storage",
            "module-ref",
            "--manifest-file",
            bundle["manifest_path"],
            "--host-url",
            host_url,
            "--path",
            module_path.name,
        ],
        capture_json=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local gossip_protocol compute smoke test")
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    build_binary()
    work_root = Path(tempfile.mkdtemp(prefix="gossip-protocol-compute-smoke-"))
    processes: List[subprocess.Popen] = []

    try:
        wallets_dir = work_root / "wallets"
        states_dir = work_root / "states"
        storage_store_dir = work_root / "storage"
        logs_dir = work_root / "logs"
        wallets_dir.mkdir()
        states_dir.mkdir()
        storage_store_dir.mkdir()
        logs_dir.mkdir()

        validator_wallets = [wallets_dir / f"validator{i}.json" for i in range(1, 4)]
        agent_wallets = [wallets_dir / f"agent{i}.json" for i in range(1, 4)]
        user_wallet = wallets_dir / "user.json"
        for wallet in validator_wallets + agent_wallets + [user_wallet]:
            create_wallet(wallet)

        validator_addresses = [wallet_address(wallet) for wallet in validator_wallets]
        agent_addresses = [wallet_address(wallet) for wallet in agent_wallets]
        user_address = wallet_address(user_wallet)

        genesis_path = work_root / "genesis.json"
        genesis = create_genesis(
            genesis_path,
            validator_wallets,
            user_address,
            validator_addresses,
        )
        storage_bundle, module_path = build_wasi_module_bundle(
            work_root,
            storage_store_dir,
            validator_addresses[0],
        )
        storage_host = StorageHostSpec(
            "127.0.0.1:9701", storage_store_dir, logs_dir / "storage.log"
        )
        processes.append(start_storage_host_process(storage_host))
        storage_host_url = f"http://{storage_host.bind}"
        wait_for_http(
            f"{storage_host_url}/v1/storage/contracts/{storage_bundle['spec']['contract_id']}/manifest",
            15,
        )
        module_ref = build_compute_module_ref(storage_bundle, storage_host_url, module_path)

        agent_specs = [
            AgentSpec("agent1", agent_wallets[0], "127.0.0.1:9601", logs_dir / "agent1.log"),
            AgentSpec("agent2", agent_wallets[1], "127.0.0.1:9602", logs_dir / "agent2.log"),
            AgentSpec("agent3", agent_wallets[2], "127.0.0.1:9603", logs_dir / "agent3.log"),
        ]
        for agent in agent_specs:
            processes.append(start_agent_process(agent))

        probe_agents_path = work_root / "probe_agents.json"
        probe_agents_path.write_text(
            json.dumps(
                {
                    "agents": [
                        {
                            "public_key": address,
                            "endpoint": f"http://{spec.bind}",
                            "api_token": AGENT_API_TOKEN,
                            "region": "local",
                            "network": "loopback",
                        }
                        for address, spec in zip(agent_addresses, agent_specs)
                    ]
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        node_specs = [
            NodeSpec(
                "node1",
                validator_wallets[0],
                states_dir / "node1",
                "127.0.0.1:9501",
                ["http://127.0.0.1:9502", "http://127.0.0.1:9503"],
                logs_dir / "node1.log",
            ),
            NodeSpec(
                "node2",
                validator_wallets[1],
                states_dir / "node2",
                "127.0.0.1:9502",
                ["http://127.0.0.1:9501", "http://127.0.0.1:9503"],
                logs_dir / "node2.log",
            ),
            NodeSpec(
                "node3",
                validator_wallets[2],
                states_dir / "node3",
                "127.0.0.1:9503",
                ["http://127.0.0.1:9501", "http://127.0.0.1:9502"],
                logs_dir / "node3.log",
            ),
        ]
        for spec in node_specs:
            spec.state_dir.mkdir()
            processes.append(start_node_process(spec, genesis_path, probe_agents_path))

        node_urls = [f"http://{spec.bind}" for spec in node_specs]
        for url in node_urls:
            wait_for_http(f"{url}/v1/control/ledger", 15)

        storage_submitted = submit_storage_create(
            node_urls[0], user_wallet, Path(storage_bundle["spec_path"])
        )
        storage_contract = fetch_storage_contract_until_active(
            node_urls[0], storage_bundle["spec"]["contract_id"], 30
        )

        compute_spec_path = work_root / "sum_job.json"
        compute_spec_path.write_text(
            json.dumps(
                {
                    "request_id": "sum-smoke",
                    "workload": {
                        "type": "integer_map",
                        "operation": "sum",
                    },
                    "shards": [
                        {"shard_id": "s1", "input": {"type": "integers", "values": [1, 2, 3]}},
                        {"shard_id": "s2", "input": {"type": "integers", "values": [4, 5]}},
                        {"shard_id": "s3", "input": {"type": "integers", "values": [6, 7]}},
                        {"shard_id": "s4", "input": {"type": "integers", "values": [8, 9, 10]}},
                    ],
                    "reducer": "sum",
                    "max_runtime_secs": 30,
                    "replication": 2,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        submitted = submit_compute_job(node_urls[0], user_wallet, compute_spec_path)
        finalized = fetch_job_until_finalized(node_urls[0], submitted["hash"], 30)
        record = finalized["finalized_compute_record"]
        if record["reduced_output"] != {"sum": 55}:
            raise RuntimeError(f"unexpected compute reduced output: {record}")
        if len(record["rewarded_receipts"]) < 2:
            raise RuntimeError(f"expected at least two rewarded compute receipts: {record}")
        assigned_agents = set()
        for receipt in record["rewarded_receipts"]:
            assigned_agents.update(receipt["body"].get("assigned_agents", {}).values())
        if not assigned_agents.intersection(agent_addresses):
            raise RuntimeError(f"compute receipts did not use configured agents: {record}")

        wasi_spec_path = work_root / "wasi_job.json"
        wasi_spec_path.write_text(
            json.dumps(
                {
                    "request_id": "wasi-smoke",
                    "workload": {
                        "type": "wasi_preview1",
                        "module_hex": EMPTY_WASI_START_HEX,
                        "args": [],
                        "env": {},
                    },
                    "shards": [
                        {
                            "shard_id": "wasi-1",
                            "input": {"type": "wasi", "stdin_hex": None, "files": {}},
                        }
                    ],
                    "reducer": "shard_outputs",
                    "max_runtime_secs": 10,
                    "replication": 2,
                    "sandbox": {
                        "max_memory_bytes": 1048576,
                        "max_fuel": 10000,
                        "max_stdout_bytes": 256,
                        "max_stderr_bytes": 256,
                        "allow_network": False,
                    },
                    "artifact_policy": {"outputs": [], "max_total_bytes": 0},
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        wasi_submitted = submit_compute_job(node_urls[0], user_wallet, wasi_spec_path)
        wasi_finalized = fetch_job_until_finalized(node_urls[0], wasi_submitted["hash"], 30)
        wasi_record = wasi_finalized["finalized_compute_record"]
        expected_wasi_output = {
            "shards": [
                {
                    "shard_id": "wasi-1",
                    "output": {"ok": True},
                    "artifacts": [],
                }
            ]
        }
        if wasi_record["reduced_output"] != expected_wasi_output:
            raise RuntimeError(f"unexpected wasi reduced output: {wasi_record}")
        if len(wasi_record["rewarded_receipts"]) < 2:
            raise RuntimeError(f"expected at least two rewarded wasi receipts: {wasi_record}")

        wasi_ref_spec_path = work_root / "wasi_module_ref_job.json"
        wasi_ref_spec_path.write_text(
            json.dumps(
                {
                    "request_id": "wasi-module-ref-smoke",
                    "workload": {
                        "type": "wasi_preview1",
                        "module_ref": module_ref,
                        "args": [],
                        "env": {},
                    },
                    "shards": [
                        {
                            "shard_id": "wasi-ref-1",
                            "input": {"type": "wasi", "stdin_hex": None, "files": {}},
                        }
                    ],
                    "reducer": "shard_outputs",
                    "max_runtime_secs": 10,
                    "replication": 2,
                    "sandbox": {
                        "max_memory_bytes": 1048576,
                        "max_fuel": 10000,
                        "max_stdout_bytes": 256,
                        "max_stderr_bytes": 256,
                        "allow_network": False,
                    },
                    "artifact_policy": {"outputs": [], "max_total_bytes": 0},
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        wasi_ref_submitted = submit_compute_job(node_urls[0], user_wallet, wasi_ref_spec_path)
        wasi_ref_finalized = fetch_job_until_finalized(
            node_urls[0], wasi_ref_submitted["hash"], 30
        )
        wasi_ref_record = wasi_ref_finalized["finalized_compute_record"]
        expected_wasi_ref_output = {
            "shards": [
                {
                    "shard_id": "wasi-ref-1",
                    "output": {"ok": True},
                    "artifacts": [],
                }
            ]
        }
        if wasi_ref_record["reduced_output"] != expected_wasi_ref_output:
            raise RuntimeError(f"unexpected wasi module_ref reduced output: {wasi_ref_record}")
        if len(wasi_ref_record["rewarded_receipts"]) < 2:
            raise RuntimeError(
                f"expected at least two rewarded wasi module_ref receipts: {wasi_ref_record}"
            )

        summary = {
            "work_root": str(work_root),
            "chain_id": genesis["chain_id"],
            "node_urls": node_urls,
            "storage_host_url": storage_host_url,
            "storage_submitted_tx_hash": storage_submitted["hash"],
            "storage_contract_id": storage_contract["contract"]["contract_id"],
            "agent_addresses": agent_addresses,
            "submitted_tx_hash": submitted["hash"],
            "reduced_output": record["reduced_output"],
            "wasi_submitted_tx_hash": wasi_submitted["hash"],
            "wasi_reduced_output": wasi_record["reduced_output"],
            "wasi_module_ref_submitted_tx_hash": wasi_ref_submitted["hash"],
            "wasi_module_ref_reduced_output": wasi_ref_record["reduced_output"],
            "rewarded_receipt_count": len(record["rewarded_receipts"]),
            "wasi_rewarded_receipt_count": len(wasi_record["rewarded_receipts"]),
            "wasi_module_ref_rewarded_receipt_count": len(
                wasi_ref_record["rewarded_receipts"]
            ),
            "logs": {
                **{spec.name: str(spec.log_path) for spec in node_specs},
                **{spec.name: str(spec.log_path) for spec in agent_specs},
                "storage": str(storage_host.log_path),
            },
        }
        print(json.dumps(summary, indent=2, sort_keys=True))

        if not args.keep_artifacts:
            shutil.rmtree(work_root)
        return 0
    finally:
        for process in processes:
            stop_process(process)
        if args.keep_artifacts and work_root.exists():
            print(f"kept artifacts in {work_root}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
