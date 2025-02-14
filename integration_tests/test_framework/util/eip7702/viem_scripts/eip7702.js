import { createWalletClient, custom, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { eip7702Actions } from 'viem/experimental';

// Helper function to handle BigInt serialization
const replacer = (key, value) =>
  typeof value === 'bigint'
    ? value.toString()
    : value;

// Helper function to create chain config
function createChainConfig(chainId) {
  return defineChain({
    id: chainId,
    name: `Chain ${chainId}`,
    network: `network ${chainId}`,
    nativeCurrency: {
      decimals: 18,
      name: 'CFX',
      symbol: 'CFX',
    },
  })
}

export async function signAuthorization({ contractAddress, chainId, nonce, privateKey }) {
  const account = privateKeyToAccount(privateKey);
  const chain = createChainConfig(chainId);
  const client = createWalletClient({
    account,
    chain,
    transport: custom({
      async request({ method, params }) {
        // Mock responses for required RPC calls
        if (method === 'eth_chainId') {
          return `0x${chainId.toString(16)}`;
        }
        throw new Error(`Unsupported method: ${method}`);
      }
    })
  }).extend(eip7702Actions());

  const authorization = await client.signAuthorization({
    account,
    chainId,
    nonce,
    contractAddress,
  });

  return authorization;
}

export async function signTransaction({ transaction, privateKey }) {
  const account = privateKeyToAccount(privateKey);
  const chain = createChainConfig(transaction.chainId);
  const client = createWalletClient({
    account,
    chain,
    transport: custom({
      async request({ method, params }) {
        // Mock responses for required RPC calls
        if (method === 'eth_chainId') {
          return `0x${transaction.chainId.toString(16)}`;
        }
        throw new Error(`Unsupported method: ${method}`);
      }
    })
  }).extend(eip7702Actions());

  const signedTransaction = await client.signTransaction({
    ...transaction,
    account,
  });

  return signedTransaction;
}

// CLI interface for Python to call
const command = process.argv[2];
const args = JSON.parse(process.argv[3]);

if (command === 'signAuthorization') {
  signAuthorization(args)
    .then(result => {
      console.log(JSON.stringify(result, replacer));
      process.exit(0);
    })
    .catch(error => {
      console.error(error);
      process.exit(1);
    });
} else if (command === 'signTransaction') {
  signTransaction(args)
    .then(result => {
      console.log(JSON.stringify(result, replacer));
      process.exit(0);
    })
    .catch(error => {
      console.error(error);
      process.exit(1);
    });
} 