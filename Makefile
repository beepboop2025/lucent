VENV := .venv
PY := $(VENV)/bin/python
ERC := $(VENV)/bin/erc7730

# Descriptor most targets act on; override on the command line.
DESC ?= registry/ens/calldata-ETHRegistrarController.json

.PHONY: setup discover fetch resolve-proxy lint audit semverify preview \
        submission attest watch watch-init all clean

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

## semverify: check the screen against on-chain movements (needs ETHERSCAN_API_KEY)
semverify:
	$(PY) scripts/semverify.py $(DESC)

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
