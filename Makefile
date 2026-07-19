VENV := .venv
PY := $(VENV)/bin/python
ERC := $(VENV)/bin/erc7730

# Descriptor most targets act on; override on the command line.
DESC ?= registry/ens/calldata-ETHRegistrarController.json

.PHONY: setup discover fetch resolve-proxy lint audit comprehend danger review \
        semverify preview submission attest watch watch-init test all clean

## setup: create the venv and install requirements
setup:
	python3.12 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r requirements.txt

## discover: classify candidate contracts. make discover SEEDS=seeds/candidates.json
discover:
	$(PY) scripts/discover.py $(SEEDS)

## fetch: cache a verified ABI. make fetch CHAIN=1 ADDR=0x...
fetch:
	$(PY) scripts/fetch_abi.py $(CHAIN) $(ADDR)

## resolve-proxy: cache a proxy's implementation ABI. make resolve-proxy CHAIN=1 ADDR=0x...
resolve-proxy:
	$(PY) scripts/resolve_proxy.py $(CHAIN) $(ADDR)

## lint: validate a descriptor (add ETHERSCAN_API_KEY for full ABI comparison)
lint:
	$(ERC) lint --skip-abi-validation $(DESC)

## audit: grade the descriptor on screen trustworthiness
audit:
	$(PY) scripts/audit.py $(DESC)

## comprehend: grade the descriptor on human COMPREHENSION risk (consequence
## sentence + risk tier with a reason, per arXiv:2601.16751)
comprehend:
	$(PY) scripts/comprehend.py $(DESC)

## danger: flag structural danger primitives (arbitrary call, delegatecall,
## selfdestruct, upgrade-and-execute) a clear screen can't make safe (2408.14621)
danger:
	$(PY) scripts/danger.py $(DESC)

## review: one publishable markdown review of a descriptor (all checks composed;
## add OUT=report.md to write a file, needs ETHERSCAN_API_KEY for semverify)
review:
	$(PY) scripts/review.py $(DESC) $(if $(OUT),--out $(OUT),)

## test: run the unit suite
test:
	$(PY) -m pytest tests/ -q

## mcp: run the pre-sign transaction-safety MCP server (stdio JSON-RPC)
mcp:
	$(PY) scripts/mcp_server.py

## semverify: check the screen against on-chain movements (needs ETHERSCAN_API_KEY;
## set SIMULATE=1 to fork-replay unmined `call` vectors, needs anvil+cast+ETH_RPC_URL)
semverify:
	$(PY) scripts/semverify.py $(DESC) $(if $(SIMULATE),--simulate,)

## resolve: expand a descriptor to resolved form
resolve:
	COLUMNS=100000 $(ERC) resolve $(DESC) >/dev/null && echo "resolved $(DESC)"

## preview: render on-device screens and write sample vectors
preview:
	$(PY) scripts/preview.py

## submission: emit the registry-PR form. make submission ENTITY=ens
submission:
	$(PY) scripts/to_submission.py $(ENTITY) $(DESC)

## attest: produce an ERC-8176 attestation over the descriptor hash
attest:
	$(PY) scripts/attest.py $(DESC)

## watch: check merged descriptors for drift
watch:
	$(PY) scripts/watch.py

## watch-init: record drift baselines for all registry descriptors
watch-init:
	$(PY) scripts/watch.py --init

## all: lint, audit, resolve, preview
all: lint audit resolve preview

## clean: remove scratch artifacts
clean:
	rm -f registry/**/_*.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
