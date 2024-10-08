// SPDX-License-Identifier: Ulicense
pragma solidity 0.8.2;

// Presale and good ERC20 contracts interaction interface
interface IContracts {
    function transfer(address, uint256) external returns (bool);
}

// Broken ERC20 transfer for rescue ERC20 tokens
interface IErc20 {
    function balanceOf(address) external returns (uint256);

    // some tokens (like USDT) not return bool as standard require
    function transfer(address, uint256) external;
}

/// @title Uniqly vesting contract
/// Users from external list (not presale contracts)
/// @author rav3n_pl
contract UniqVestingSE {
    // user is eligible to receive bonus NFT tokens (default=0)
    mapping(address => uint256) internal _bonus;

    /// it will be used by future contract
    function bonus(address user) external view returns (uint256) {
        return _bonus[user];
    }

    // always true, for ABI/backend compatibility
    function initialized(address) external pure returns (bool) {
        return true;
    }

    // total amount of token bought by presale contracts (default=0)
    mapping(address => uint256) internal _tokensTotal;

    function tokensTotal(address user) external view returns (uint256) {
        return _tokensTotal[user];
    }

    // percentage already withdrawn by user (default=0)
    mapping(address => uint256) internal _pctWithdrawn;

    function pctWithdrawn(address user) external view returns (uint256) {
        return _pctWithdrawn[user];
    }

    /// ERC20 token contract address
    address public immutable token;

    /// timestamp that users can start withdrawals
    uint256 public immutable dateStart;
    /// address of contract owner
    address public owner;

    // Manually disable adding investors to match main contract date
    bool addDisabled;

    function closeAdd() external onlyOwner {
        addDisabled = true;
    }

    /**
    @dev contract constructor
    @param _token address of ERC20 token contract
    @param _dateStart uint256 timestamp from when users can start withdrawing tokens 
    */
    constructor(address _token, uint256 _dateStart) {
        token = _token;
        dateStart = _dateStart;
        owner = msg.sender;
    }

    // for ABI/backend compatibility
    function calc() external view returns (uint256) {
        return _tokensTotal[msg.sender];
    }

    /**
    @dev Number of tokens eligible to withdraw
    @return number of tokens available for user
     */
    function balanceOf(address user) external view returns (uint256) {
        return (_tokensTotal[user] * (100 - _pctWithdrawn[user])) / 100;
    }

    /**
    @dev user call this function to withdraw tokens
    @return bool true if any token transfer made
    */
    function claim() external returns (bool) {
        // can't work before timestamp
        require(block.timestamp > dateStart, "Initial vesting in progress");

        // initial percent is 20
        uint256 pct = 20;
        uint256 time = dateStart + 1 weeks;
        // every week to date
        while (time < block.timestamp) {
            pct += 4;
            // can't be more than 100
            if (pct == 100) {
                break;
            }
            time += 1 weeks;
        }
        // do we have any % of tokens to withdraw?
        if (pct > _pctWithdrawn[msg.sender]) {
            uint256 thisTime = pct - _pctWithdrawn[msg.sender];
            // is user a patient one?
            // you've got a prize/s in near future!
            if (pct > 59) {
                // 60% for 1st bonus, even when initial 20% claimed
                // but no bonus at all if claimed more than 20%
                if (_pctWithdrawn[msg.sender] < 21) {
                    _bonus[msg.sender] = 1;
                    // second bonus after 100% and max 20% withdrawn
                    if (pct == 100 && thisTime > 79) {
                        _bonus[msg.sender] = 2;
                    }
                }
            }
            // how many tokens it would be...
            uint256 amt = (_tokensTotal[msg.sender] * thisTime) / 100;
            // yes, no reentrance please
            _pctWithdrawn[msg.sender] += thisTime;
            // transfer tokens counted
            return IContracts(token).transfer(msg.sender, amt);
        }
        // did nothing
        return false;
    }

    modifier onlyOwner {
        require(msg.sender == owner, "Only for Owner");
        _;
    }

    // change ownership in two steps to be sure about owner address
    address public newOwner;

    // only current owner can delegate new one
    function giveOwnership(address _newOwner) external onlyOwner {
        newOwner = _newOwner;
    }

    // new owner need to accept ownership
    function acceptOwnership() external {
        require(msg.sender == newOwner, "You are not New Owner");
        newOwner = address(0);
        owner = msg.sender;
    }

    /**
    @dev Add investor to vesting contract that not used collection contract
    @param addr - address to add
    @param amount - tokens due
    */
    function addInvestor(address addr, uint256 amount) external onlyOwner {
        require(!addDisabled, "Too late do add investors");
        _addInvestor(addr, amount);
    }

    /**
    @dev Add investors in bulk
    @param addr table of addresses
    @param amount table of amounts
    */
    function addInvestors(address[] calldata addr, uint256[] calldata amount)
        external
        onlyOwner
    {
        require(!addDisabled, "Too late do add investors");
        require(addr.length == amount.length, "Data length not match");
        for (uint256 i = 0; i < addr.length; i++) {
            _addInvestor(addr[i], amount[i]);
        }
    }

    // internal function adding investors
    function _addInvestor(address addr, uint256 amt) internal {
        require(_tokensTotal[addr] == 0, "Address already on list");
        _tokensTotal[addr] = amt;
    }

    /**
    @dev Function to recover accidentally send ERC20 tokens
    @param _token ERC20 token address
    */
    function rescueERC20(address _token) external onlyOwner {
        uint256 amt = IErc20(_token).balanceOf(address(this));
        require(amt > 0, "Nothing to rescue");
        IErc20(_token).transfer(owner, amt);
    }
}