# Detecti
Detecti serves as a semi-automatic tool, capable of examining specific sections of Solidity Smart Contracts code that may raise concerns for the
user (perhaps because of a dubious alert generated by another tool). 

Detecti was developed to assess three distinct categories of vulnerabilities: Unchecked Call Return Values, Timestamp Dependence, and Reentrancy.

Our primary objective is to scrutinize segments of the code that have triggered alerts from other tools, with a clear emphasis on identifying potential false positives.
In rare instances, our aim is also to uncover possible false negatives.

The need for such a tool arises from a problem common to most of the tools available to date for vulnerability analysis of Smart Contracts written in Solidity: the production of a considerable number of **false positives**.

## Getting Started
The first step will be to install [Surya](https://github.com/ConsenSys/surya), the parser used at the base of our code analysis tool.

Then you will need to verify that python is properly installed on your machine, otherwise install it.

At this point it will be sufficient to download the file Detecti.py, which you can find in this repository, and run it (remember to provide that file with execution permissions) providing as an argument the path to the Solidity file to be analyzed.
```
./Detecti.py test.sol
```
## Tests
`SCs_test` folder contains smart contracts, currently deployed on the Ethereum blockchain, serving as test cases to assess the tool's performance. Each vulnerability category includes 10 smart contracts, located within their respective subfolders: `Ree` for Reentrancy, `TD` for Timestamp Dependence, and `UEC` for Unchecked Call Return Value, also called Unchecked Externall Call.

To easily and quickly reproduce the tests we performed on all 30 smart contracts we provide the `script.py` file.

## License
GPLv3.0



