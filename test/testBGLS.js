const hre = require('hardhat');
const {assert} = require('chai');
const {ethers} = require('hardhat');
const bls254 = require('./blsbn254');
const {BigNumber} = require("ethers");

const formatG1 = (p) => p.x.toHexString() + ',' + p.y.toHexString();
const equalG1 = (p, q) => p.x.eq(q.x) && p.y.eq(q.y);

function convertG1(mclG1) {
    const hex = bls254.g1ToHex(mclG1);
    return {x: BigNumber.from(hex[0]), y: BigNumber.from(hex[1])};
}

function convertG2(mclG2) {
    const hex = bls254.g2ToHex(mclG2);
    return {
        xr: BigNumber.from(hex[0]),
        xi: BigNumber.from(hex[1]),
        yr: BigNumber.from(hex[2]),
        yi: BigNumber.from(hex[3]),
    };
}

describe('BGLS', function () {
    let bgls;

    const message = '0x6162636566676869';
    let res;

    before(async () => {
        await bls254.init();
        const BGLS = await hre.ethers.getContractFactory('BGLS');
        bgls = await BGLS.deploy();
        await bgls.deployed();
    });

    it("should hash to same G1 point", async () => {
        const P1 = await bgls.callStatic.hashToG1(message);
        const Q1 = convertG1(bls254.hashToG1(message));

        assert(equalG1(P1, Q1));
    });

    it("should verify valid signature", async () => {
        const keypair = bls254.newKeyPair(); // pubKey: G2, secret: Fr (BigNumber)
        res = bls254.sign(message, keypair.secret); // signature: G1, M: G1
        const sigG1 = convertG1(res.signature);
        const pkG2 = convertG2(keypair.pubkey);

        res = await bgls.callStatic.checkSignature(message, sigG1, pkG2);
        assert(res === true);
    });

    it("should not verify bad signature", async () => {
        const keypair = bls254.newKeyPair();
        res = bls254.sign(message, keypair.secret);
        const sigG1 = convertG1(res.signature);
        const pkG2 = convertG2(keypair.pubkey);

        res = bls254.verify(message, keypair.pubkey, res.signature);
        assert(res === true);

        // use a random G1 point as signature
        res = await bgls.callStatic.checkSignature(message, convertG1(bls254.randG1()), pkG2);
        assert(res === false);

        // use a random G2 point as pubkey
        res = await bgls.callStatic.checkSignature(message, sigG1, convertG2(bls254.randG2()));
        assert(res === false);
    });

    it("should verify valid aggregated signature with aggregated public key", async () => {
        const key1 = bls254.newKeyPair();
        const key2 = bls254.newKeyPair();

        const aggPk = bls254.aggreagate(key1.pubkey, key2.pubkey);

        const res1 = bls254.sign(message, key1.secret);
        const res2 = bls254.sign(message, key2.secret);

        const aggSig = bls254.aggreagate(res1.signature, res2.signature);
        res = bls254.verify(message, aggPk, aggSig);
        assert(res === true);

        res = await bgls.callStatic.checkSignature(message, convertG1(aggSig), convertG2(aggPk));
        assert(res === true);
    });

    it("should not verify bad aggregate signature or with wrong aggragate pubkey", async() => {
        const key1 = bls254.newKeyPair();
        const key2 = bls254.newKeyPair();

        const aggPk = bls254.aggreagate(key1.pubkey, key2.pubkey);

        const res1 = bls254.sign(message, key1.secret);
        const res2 = bls254.sign(message, key2.secret);

        const aggSig = bls254.aggreagate(res1.signature, res2.signature);
        res = bls254.verify(message, aggPk, aggSig);
        assert(res === true);

        res = await bgls.callStatic.checkSignature(message, convertG1(res1.signature), convertG2(aggPk));
        assert(res === false);

        res = await bgls.callStatic.checkSignature(message, convertG1(res2.signature), convertG2(aggPk));
        assert(res === false);

        res = await bgls.callStatic.checkSignature(message, convertG1(aggSig), convertG2(key1.pubkey));
        assert(res === false);

        res = await bgls.callStatic.checkSignature(message, convertG1(aggSig), convertG2(key2.pubkey));
        assert(res === false);
    });
});

