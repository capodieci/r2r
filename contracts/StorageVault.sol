// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// R2R storage-market settlement vault. One instance per chain; ownerless,
/// non-upgradeable, no pause switch. See docs/settlement-design.md.
///
/// Roles:
///   payer  -- a wallet's payment key. Deposits USDC, signs cumulative
///             vouchers off-chain. Deliberately unlinked to any R2R identity.
///   payout -- a relay operator's address, bonded at registration. The only
///             kind of address that can be redeemed to.
///
/// A voucher is the EIP-191 personal-sign of
///   keccak256("r2r-voucher-v1" || address(this) || chainid || payee || cumulative)
/// and states "I owe `payee` a lifetime total of `cumulative` micro-USDC".
/// Redemption pays the delta over what was already settled, so the newest
/// voucher subsumes all older ones (aggregation), and replay is harmless
/// (`settled` only moves forward).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract R2RStorageVault {
    IERC20 public immutable usdc;

    uint256 public constant BOND = 10_000_000; // 10 USDC, 6 decimals
    uint256 public constant EXIT_NOTICE = 60 days;
    // Longer than one relay epoch (31 days): a relay that settles every
    // epoch can never be front-run by a deposit withdrawal.
    uint256 public constant WITHDRAW_DELAY = 40 days;

    struct Relay {
        address payout;
        uint64 registeredAt;
        uint64 exitAt; // 0 = active
    }

    mapping(bytes32 => Relay) public relays;            // node id -> registration
    mapping(address => uint256) public registeredPayout; // payout -> live registrations
    mapping(address => uint256) public balances;         // payer -> deposit
    mapping(address => uint256) public withdrawAmount;
    mapping(address => uint256) public withdrawAfter;
    mapping(address => mapping(address => uint256)) public settled; // payer -> payout -> cumulative
    mapping(address => uint256) public lifetimeEarned;   // payout -> total redeemed, ever

    event RelayRegistered(bytes32 indexed nodeId, address indexed payout);
    event ExitStarted(bytes32 indexed nodeId, address indexed payout, uint256 exitAt);
    event BondWithdrawn(bytes32 indexed nodeId, address indexed payout);
    event Deposited(address indexed payer, uint256 amount);
    event WithdrawRequested(address indexed payer, uint256 amount, uint256 after_);
    event Withdrawn(address indexed payer, uint256 amount);
    event Redeemed(address indexed payer, address indexed payee, uint256 delta, uint256 cumulative);

    constructor(IERC20 usdc_) {
        usdc = usdc_;
    }

    // --- relay registry ----------------------------------------------------

    function register(bytes32 nodeId) external {
        require(nodeId != bytes32(0), "node id");
        require(relays[nodeId].payout == address(0), "taken");
        relays[nodeId] = Relay(msg.sender, uint64(block.timestamp), 0);
        registeredPayout[msg.sender] += 1;
        require(usdc.transferFrom(msg.sender, address(this), BOND), "bond");
        emit RelayRegistered(nodeId, msg.sender);
    }

    function startExit(bytes32 nodeId) external {
        Relay storage r = relays[nodeId];
        require(r.payout == msg.sender, "not yours");
        require(r.exitAt == 0, "exiting");
        r.exitAt = uint64(block.timestamp + EXIT_NOTICE);
        emit ExitStarted(nodeId, msg.sender, r.exitAt);
    }

    function withdrawBond(bytes32 nodeId) external {
        Relay memory r = relays[nodeId];
        require(r.payout == msg.sender, "not yours");
        require(r.exitAt != 0 && block.timestamp >= r.exitAt, "notice");
        delete relays[nodeId];
        registeredPayout[msg.sender] -= 1;
        require(usdc.transfer(msg.sender, BOND), "refund");
        emit BondWithdrawn(nodeId, msg.sender);
    }

    // --- payer deposits ----------------------------------------------------

    function deposit(uint256 amount) external {
        require(amount > 0, "amount");
        balances[msg.sender] += amount;
        require(usdc.transferFrom(msg.sender, address(this), amount), "transfer");
        emit Deposited(msg.sender, amount);
    }

    function requestWithdraw(uint256 amount) external {
        require(amount > 0 && amount <= balances[msg.sender], "amount");
        withdrawAmount[msg.sender] = amount;
        withdrawAfter[msg.sender] = block.timestamp + WITHDRAW_DELAY;
        emit WithdrawRequested(msg.sender, amount, withdrawAfter[msg.sender]);
    }

    function withdraw() external {
        uint256 amount = withdrawAmount[msg.sender];
        require(amount > 0, "none");
        require(block.timestamp >= withdrawAfter[msg.sender], "delay");
        // Redemptions during the window may have shrunk the balance.
        if (amount > balances[msg.sender]) amount = balances[msg.sender];
        withdrawAmount[msg.sender] = 0;
        withdrawAfter[msg.sender] = 0;
        balances[msg.sender] -= amount;
        require(usdc.transfer(msg.sender, amount), "transfer");
        emit Withdrawn(msg.sender, amount);
    }

    // --- settlement ---------------------------------------------------------

    /// Anyone may submit (a helper can pay the gas); the money always goes to
    /// the registered payout address named inside the signed voucher.
    function redeem(address payee, uint256 cumulative, bytes calldata sig) public {
        require(registeredPayout[payee] > 0, "payee not registered");
        address payer = recover(payee, cumulative, sig);
        uint256 done = settled[payer][payee];
        require(cumulative > done, "nothing new");
        uint256 delta = cumulative - done;
        // Pay what the balance covers; the remainder stays redeemable with
        // the same voucher after the payer tops up.
        if (delta > balances[payer]) delta = balances[payer];
        require(delta > 0, "unfunded");
        settled[payer][payee] = done + delta;
        balances[payer] -= delta;
        lifetimeEarned[payee] += delta;
        require(usdc.transfer(payee, delta), "transfer");
        emit Redeemed(payer, payee, delta, done + delta);
    }

    function redeemBatch(address payee, uint256[] calldata cumulatives, bytes[] calldata sigs)
        external
    {
        require(cumulatives.length == sigs.length, "length");
        for (uint256 i = 0; i < cumulatives.length; i++) {
            redeem(payee, cumulatives[i], sigs[i]);
        }
    }

    function recover(address payee, uint256 cumulative, bytes calldata sig)
        internal
        view
        returns (address)
    {
        require(sig.length == 65, "sig length");
        bytes32 inner =
            keccak256(abi.encodePacked("r2r-voucher-v1", address(this), block.chainid, payee, cumulative));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        // Reject the malleable half of the s range, as geth does.
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "sig s");
        address payer = ecrecover(digest, v, r, s);
        require(payer != address(0), "sig");
        return payer;
    }
}
