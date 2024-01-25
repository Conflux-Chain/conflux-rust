from produce_tx import transfer
from produce_tx import uniswap
from produce_tx import log
from produce_tx import account

if __name__ == "__main__":
    log.set_level(1)

    transfer.deploy_native()
    transfer.deploy_erc20()

    uniswap.deploy()
    # account.build_account_map(range(100_000))
    # account.debug()
