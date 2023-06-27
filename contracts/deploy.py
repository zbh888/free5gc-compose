import web3
import solcx
from eth_account import Account
from eth_account.messages import encode_defunct
from solcx import compile_source

# Config Part
w3 = web3.Web3(web3.HTTPProvider('http://127.0.0.1:7545'))
# This part is assuming AMF knows the IMSI, so the address can be uint256.
# This part is mainly for testing
availableUEs = [1,2,3,4,5,6]
salts = [1,2,3,4,5,6]
banUEs = [4,5,6]
contractName = "guardtest.sol"
# This part is assuming AMF does not know IMSI, which should be the actual deployment.
#availableUEs = []
#salts = [1,2,3,4,5,6]
#banUEs = []
#contractName = "guard.sol"

# This part is the function definition.
def chain_deploy():
    v = "0.8.4"
    with open(contractName, "r") as f:
        contract_source_code = f.read()
    solcx.install_solc(v)

    compiled_sol = compile_source(contract_source_code, output_values=['abi', 'bin'])
    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']

    # This is the Home Network which is the owner of the contract
    w3.eth.default_account = w3.eth.accounts[0]

    # Deployment
    Guard = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Guard.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    print("Contract Address: ", contract_address)
    return contract_address, abi

def chain_banUser(addrs, contract):
    tx_hash = contract.functions.banUser(addrs).transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

def chain_getStatus(addrs, contract):
    return contract.functions.getSaltStatus(addrs).call()

def chain_putUE(addrs, salt, contract):
    tx_hash = contract.functions.updateSalt(addrs, salt).transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

contract_address, abi = chain_deploy()
contract = w3.eth.contract(address=contract_address, abi=abi)

chain_putUE(availableUEs, salts, contract) # setup the UEs
chain_banUser(banUEs, contract) # ban some UEs
print(getStatus(availableUEs, contract)) # See the result confirming it is working
