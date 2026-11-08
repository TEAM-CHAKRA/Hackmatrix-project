const { expect } = require('chai');
const { ethers } = require('hardhat');

const h = (s) => ethers.sha256(ethers.toUtf8Bytes(s)); // any 32-byte value
const ID = 'INV-20261108-7F3A2C9D1E4B8A5F';
const Status = { Registered: 0n, Validated: 1n, Disputed: 2n };

describe('CyberlensRegistry', () => {
  let registry, owner, registrar, stranger;

  beforeEach(async () => {
    [owner, registrar, stranger] = await ethers.getSigners();
    registry = await (await ethers.getContractFactory('CyberlensRegistry')).deploy();
    await registry.waitForDeployment();
  });

  it('sets the deployer as owner and registrar', async () => {
    expect(await registry.owner()).to.equal(owner.address);
    expect(await registry.registrars(owner.address)).to.equal(true);
  });

  it('registers a report and exposes it by ID and by hash', async () => {
    const tx = await registry.registerReport(ID, h('a'));
    const receipt = await tx.wait();
    await expect(tx).to.emit(registry, 'ReportRegistered').withArgs(ID, h('a'), 1n, owner.address);

    const rec = await registry.getRecord(ID);
    expect(rec.reportHash).to.equal(h('a'));
    expect(rec.revision).to.equal(1n);
    expect(rec.status).to.equal(Status.Registered);
    expect(rec.blockNumber).to.equal(BigInt(receipt.blockNumber));
    expect(rec.reporter).to.equal(owner.address);
    expect(await registry.isRegistered(ID)).to.equal(true);

    const [id, byHash, hashRevision] = await registry.getRecordByHash(h('a'));
    expect(id).to.equal(ID);
    expect(byHash.reportHash).to.equal(h('a'));
    expect(hashRevision).to.equal(1n);
  });

  it('is idempotent for the same ID and hash (no second event, same record)', async () => {
    await (await registry.registerReport(ID, h('a'))).wait();
    const first = await registry.getRecord(ID);
    const tx = await registry.registerReport(ID, h('a'));
    await expect(tx).not.to.emit(registry, 'ReportRegistered');
    const again = await registry.getRecord(ID);
    expect(again.timestamp).to.equal(first.timestamp);
    expect(again.revision).to.equal(1n);
  });

  it('rejects a different hash for an existing ID (must use reviseReport)', async () => {
    await (await registry.registerReport(ID, h('a'))).wait();
    await expect(registry.registerReport(ID, h('b'))).to.be.revertedWithCustomError(registry, 'HashMismatchUseRevise');
  });

  it('rejects reusing a hash for a different ID', async () => {
    await (await registry.registerReport(ID, h('a'))).wait();
    await expect(registry.registerReport('INV-OTHER', h('a'))).to.be.revertedWithCustomError(registry, 'HashAlreadyUsed');
  });

  it('rejects zero hashes and empty or oversized IDs', async () => {
    await expect(registry.registerReport(ID, ethers.ZeroHash)).to.be.revertedWithCustomError(registry, 'InvalidHash');
    await expect(registry.registerReport('', h('a'))).to.be.revertedWithCustomError(registry, 'InvalidId');
    await expect(registry.registerReport('X'.repeat(65), h('a'))).to.be.revertedWithCustomError(registry, 'InvalidId');
  });

  it('revises a report: revision increases, old hash is marked superseded, status resets', async () => {
    await (await registry.registerReport(ID, h('a'))).wait();
    await (await registry.updateStatus(ID, Status.Validated)).wait();

    await expect(registry.reviseReport(ID, h('b'))).to.emit(registry, 'ReportRevised').withArgs(ID, h('a'), h('b'), 2n);
    const rec = await registry.getRecord(ID);
    expect(rec.reportHash).to.equal(h('b'));
    expect(rec.revision).to.equal(2n);
    expect(rec.status).to.equal(Status.Registered);

    const [, current, oldHashRevision] = await registry.getRecordByHash(h('a'));
    expect(oldHashRevision).to.equal(1n);
    expect(current.revision).to.equal(2n); // old hash is superseded

    await (await registry.reviseReport(ID, h('c'))).wait();
    expect((await registry.getRecord(ID)).revision).to.equal(3n);
  });

  it('revision rules: must exist, must differ, hash must be unused', async () => {
    await expect(registry.reviseReport(ID, h('a'))).to.be.revertedWithCustomError(registry, 'NotFound');
    await (await registry.registerReport(ID, h('a'))).wait();
    await (await registry.registerReport('INV-2', h('x'))).wait();
    await expect(registry.reviseReport(ID, h('a'))).to.be.revertedWithCustomError(registry, 'SameHash');
    await expect(registry.reviseReport(ID, h('x'))).to.be.revertedWithCustomError(registry, 'HashAlreadyUsed');
  });

  it('only the owner can update status', async () => {
    await (await registry.registerReport(ID, h('a'))).wait();
    await expect(registry.connect(stranger).updateStatus(ID, Status.Disputed)).to.be.revertedWithCustomError(registry, 'NotOwner');
    await expect(registry.updateStatus(ID, Status.Disputed)).to.emit(registry, 'ReportStatusUpdated').withArgs(ID, Status.Disputed);
    expect((await registry.getRecord(ID)).status).to.equal(Status.Disputed);
    await expect(registry.updateStatus('INV-MISSING', Status.Validated)).to.be.revertedWithCustomError(registry, 'NotFound');
  });

  it('only registrars can write; owner manages registrars', async () => {
    await expect(registry.connect(stranger).registerReport(ID, h('a'))).to.be.revertedWithCustomError(registry, 'NotRegistrar');
    await expect(registry.connect(stranger).setRegistrar(stranger.address, true)).to.be.revertedWithCustomError(registry, 'NotOwner');
    await (await registry.setRegistrar(registrar.address, true)).wait();
    await expect(registry.connect(registrar).registerReport(ID, h('a'))).to.emit(registry, 'ReportRegistered');
    await (await registry.setRegistrar(registrar.address, false)).wait();
    await expect(registry.connect(registrar).reviseReport(ID, h('b'))).to.be.revertedWithCustomError(registry, 'NotRegistrar');
  });

  it('unknown IDs and hashes return empty results instead of reverting', async () => {
    const rec = await registry.getRecord('INV-NONE');
    expect(rec.timestamp).to.equal(0n);
    expect(await registry.isRegistered('INV-NONE')).to.equal(false);
    const [id, , rev] = await registry.getRecordByHash(h('nope'));
    expect(id).to.equal('');
    expect(rev).to.equal(0n);
  });

  it('transfers ownership', async () => {
    await (await registry.transferOwnership(registrar.address)).wait();
    expect(await registry.owner()).to.equal(registrar.address);
    await expect(registry.transferOwnership(stranger.address)).to.be.revertedWithCustomError(registry, 'NotOwner');
  });
});
