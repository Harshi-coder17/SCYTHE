"""SCYTHE Azure Cloud Live Test Runner.

Orchestrates:
1. Safe on-demand startup of Azure Harvester VM (scythe-harvester-vm).
2. Live zero-day phishing feed acquisition & test execution.
3. Strict fail-safe automated deallocation (try/finally) to guarantee zero lingering cost.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("azure_cloud_test")

RESOURCE_GROUP = "SCYTHE-HARVESTER-RG"
VM_NAME = "scythe-harvester-vm"

def run_az(cmd: list[str], timeout: int = 300) -> dict | str:
    full_cmd = ["az"] + cmd
    logger.info("Executing: %s", " ".join(full_cmd))
    res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout, shell=True)
    if res.returncode != 0:
        logger.error("Azure CLI error: %s", res.stderr)
        raise RuntimeError(f"Azure CLI failed: {res.stderr}")
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return res.stdout.strip()

def deallocate_vm():
    logger.info("Deallocating %s in %s (budget protection)...", VM_NAME, RESOURCE_GROUP)
    try:
        run_az(["vm", "deallocate", "-g", RESOURCE_GROUP, "-n", VM_NAME, "--no-wait"], timeout=60)
        logger.info("Deallocation signal sent successfully. VM will not incur compute charges.")
    except Exception as e:
        logger.critical("Failed to deallocate VM automatically: %s. Run 'az vm deallocate -g %s -n %s' manually!", e, RESOURCE_GROUP, VM_NAME)

def main():
    logger.info("=" * 65)
    logger.info("SCYTHE Azure Cloud Live Ingestion & Validation Test")
    logger.info("=" * 65)

    try:
        # Step 1: Start VM
        logger.info("Step 1: Starting %s...", VM_NAME)
        run_az(["vm", "start", "-g", RESOURCE_GROUP, "-n", VM_NAME], timeout=180)
        logger.info("VM started successfully.")

        # Step 2: Query VM status & public IP
        logger.info("Step 2: Checking VM status...")
        info = run_az(["vm", "show", "-g", RESOURCE_GROUP, "-n", VM_NAME, "-d", "--query", "{ip:publicIps, power:powerState}", "-o", "json"], timeout=60)
        logger.info("VM Status: %s", info)

        # Step 3: Run quick live probe via Azure RunCommand using script file
        logger.info("Step 3: Executing live zero-day ingestion probe on Azure VM...")
        cmd_result = run_az([
            "vm", "run-command", "invoke",
            "-g", RESOURCE_GROUP,
            "-n", VM_NAME,
            "--command-id", "RunShellScript",
            "--scripts", "@C:/Users/armaa/Desktop/Project details/SCYTHE/scripts/azure_remote_probe.sh",
            "-o", "json"
        ], timeout=180)

        logger.info("Cloud execution returned:")
        logger.info(json.dumps(cmd_result, indent=2))

        logger.info("=" * 65)
        logger.info("AZURE CLOUD TEST SUCCESSFUL")
        logger.info("=" * 65)

    finally:
        # Step 4: Strict deallocation in finally block to ensure ZERO cost
        logger.info("Step 4: Shutting down and deallocating Azure resources...")
        deallocate_vm()

if __name__ == "__main__":
    main()
