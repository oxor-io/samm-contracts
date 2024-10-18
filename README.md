# Safe Anonymization Mail Module Contracts

This repository contains the contracts part of the SAMM project.

## Description

This implementation of the contracts is for the Noir grant.

Our main concept revolves around creating a module for the Safe multisig that ensures the anonymity of all its participants using ZK-SNARK technology.

The details are outlined in:
- [Technical docs](https://www.notion.so/oxorioteam/SAMM-technical-requirements-7c42604654ba408ea68176fb609cf04b)
- [Grant Proposal](https://github.com/orgs/noir-lang/discussions/5813)

## Repository Structure

This repository contains a Foundry project and consists of:
- **src folder** - contains the source code of SAMM smart contracts.
- **test folder** - contains tests for SAMM smart contracts.

## Dependencies

The contracts are written in Solidity and utilize the Foundry development framework. To work correctly, the following version is required:
- `forge` 0.2.0

### Install the Required Version of Foundry 

To get started with this project, you need to install Foundry. 
1. To install Foundry, open your terminal and run the following command:
    ```
        curl -L https://foundry.paradigm.xyz | bash
    ```
2. Close the terminal, open another one, and run:
    ```
        foundryup --version 0.2.0
    ```
Complete instructions for installing Foundry can be [found here](https://book.getfoundry.sh/getting-started/installation).

## Compilation

To install dependencies, run:
```
  forge install
```
To compile the Foundry project, run:

```
  forge build
```

## Run Tests

Before running tests, you will need to set up an `.env` file in the project root with an Ethereum API key. Create a `.env` file and add the following:

```
  MAINNET_RPC={your-ethereum-api-key}
```

Replace `your-ethereum-api-key` with your actual API key. Then, you can run tests with the following command:

```
  forge test
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
