# Safe Anonymization Mail Module (SAMM)

## Description

This is an implementation of the contract for the Noir grant.

Our key concept is centered around the creation of a module for Safe multisig that ensures the anonymity of all its participants using ZK-SNARK technology.

The details are described in:

- [Technical docs](https://www.notion.so/oxorioteam/SAMM-technical-requirements-7c42604654ba408ea68176fb609cf04b)

## Requirements

- Foundry

## Installation

To get started with this project, you need to install Foundry. Follow the instructions [here](https://book.getfoundry.sh/getting-started/installation).

```bash
forge install
```

## Testing

Before running tests, you will need to set up an `.env` file in the project root with an Ethereum API key. Create a `.env` file and add the following:

```
MAINNET_RPC={your-ethereum-api-key}
```

Replace `your-ethereum-api-key` with your actual API key. Then, you can run tests with the following command:

```bash
forge test
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
