// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title CyberlensRegistry
 * @notice Anchors SHA-256 fingerprints of CYBERLENS reports on-chain so anyone
 *         can later prove a report was not altered. Only hashes and IDs are
 *         stored: no URLs, message text or other free-text metadata.
 *
 * Rules (docs/backend.md amendments 11 and 14):
 *  - Lookup by report ID and by hash.
 *  - registerReport is idempotent for the same (id, hash).
 *  - A hash can never be reused by a different ID.
 *  - Changing a report's hash requires reviseReport; revision numbers increase.
 *  - Status (Registered, Validated, Disputed) can only be changed by the owner.
 *  - Writes are restricted to authorised registrars (the CYBERLENS backend
 *    signer), so nobody can front-run an ID with a fake hash.
 */
contract CyberlensRegistry {
    enum ReportStatus {
        Registered,
        Validated,
        Disputed
    }

    struct Record {
        bytes32 reportHash;
        uint256 timestamp;
        uint256 blockNumber;
        uint256 revision;
        ReportStatus status;
        address reporter;
    }

    address public owner;
    mapping(address => bool) public registrars;

    mapping(bytes32 => Record) private _records; // keccak256(reportId) => record
    mapping(bytes32 => string) private _idByHash; // reportHash => reportId
    mapping(bytes32 => uint256) private _revisionOfHash; // reportHash => revision it was registered as

    event ReportRegistered(string reportId, bytes32 indexed reportHash, uint256 revision, address indexed reporter);
    event ReportRevised(string reportId, bytes32 indexed previousHash, bytes32 indexed newHash, uint256 revision);
    event ReportStatusUpdated(string reportId, ReportStatus status);
    event RegistrarUpdated(address indexed account, bool allowed);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotRegistrar();
    error InvalidHash();
    error InvalidId();
    error NotFound();
    error HashAlreadyUsed();
    error HashMismatchUseRevise();
    error SameHash();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyRegistrar() {
        if (!registrars[msg.sender]) revert NotRegistrar();
        _;
    }

    constructor() {
        owner = msg.sender;
        registrars[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit RegistrarUpdated(msg.sender, true);
    }

    // ---------------------------------------------------------------- admin

    function setRegistrar(address account, bool allowed) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        registrars[account] = allowed;
        emit RegistrarUpdated(account, allowed);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ---------------------------------------------------------------- writes

    /// @notice Register a report fingerprint. Idempotent for the same (id, hash).
    /// @return revision The record's current revision (1 for a new record).
    function registerReport(string calldata reportId, bytes32 reportHash) external onlyRegistrar returns (uint256 revision) {
        if (reportHash == bytes32(0)) revert InvalidHash();
        _checkId(reportId);
        bytes32 key = keccak256(bytes(reportId));
        Record storage rec = _records[key];

        if (rec.timestamp != 0) {
            if (rec.reportHash != reportHash) revert HashMismatchUseRevise();
            return rec.revision; // already registered: no-op
        }
        if (bytes(_idByHash[reportHash]).length != 0) revert HashAlreadyUsed();

        rec.reportHash = reportHash;
        rec.timestamp = block.timestamp;
        rec.blockNumber = block.number;
        rec.revision = 1;
        rec.status = ReportStatus.Registered;
        rec.reporter = msg.sender;
        _idByHash[reportHash] = reportId;
        _revisionOfHash[reportHash] = 1;

        emit ReportRegistered(reportId, reportHash, 1, msg.sender);
        return 1;
    }

    /// @notice Replace a report's hash with a new revision (revision increases by 1).
    function reviseReport(string calldata reportId, bytes32 newHash) external onlyRegistrar returns (uint256 revision) {
        if (newHash == bytes32(0)) revert InvalidHash();
        bytes32 key = keccak256(bytes(reportId));
        Record storage rec = _records[key];
        if (rec.timestamp == 0) revert NotFound();
        if (rec.reportHash == newHash) revert SameHash();
        if (bytes(_idByHash[newHash]).length != 0) revert HashAlreadyUsed();

        bytes32 previous = rec.reportHash;
        rec.reportHash = newHash;
        rec.revision += 1;
        rec.timestamp = block.timestamp;
        rec.blockNumber = block.number;
        rec.status = ReportStatus.Registered; // a new revision must be re-validated
        rec.reporter = msg.sender;
        _idByHash[newHash] = reportId;
        _revisionOfHash[newHash] = rec.revision;

        emit ReportRevised(reportId, previous, newHash, rec.revision);
        return rec.revision;
    }

    /// @notice Owner-only status change (Registered, Validated, Disputed).
    function updateStatus(string calldata reportId, ReportStatus newStatus) external onlyOwner {
        Record storage rec = _records[keccak256(bytes(reportId))];
        if (rec.timestamp == 0) revert NotFound();
        rec.status = newStatus;
        emit ReportStatusUpdated(reportId, newStatus);
    }

    // ---------------------------------------------------------------- reads

    /// @notice Current record for an ID. Returns an all-zero record if not registered.
    function getRecord(string calldata reportId) external view returns (Record memory) {
        return _records[keccak256(bytes(reportId))];
    }

    function isRegistered(string calldata reportId) external view returns (bool) {
        return _records[keccak256(bytes(reportId))].timestamp != 0;
    }

    /// @notice Look up by hash. `reportId` is empty if the hash was never registered.
    ///         `hashRevision` is the revision that hash belonged to; if it is lower
    ///         than `rec.revision`, the hash has been superseded by a newer revision.
    function getRecordByHash(bytes32 reportHash)
        external
        view
        returns (string memory reportId, Record memory rec, uint256 hashRevision)
    {
        reportId = _idByHash[reportHash];
        if (bytes(reportId).length != 0) {
            rec = _records[keccak256(bytes(reportId))];
            hashRevision = _revisionOfHash[reportHash];
        }
    }

    function _checkId(string calldata reportId) private pure {
        uint256 len = bytes(reportId).length;
        if (len == 0 || len > 64) revert InvalidId();
    }
}
