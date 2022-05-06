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

describe('WeightedMultiSig', function () {
    let wms;

    const num = 4;
    let res;

    const weights = [1, 1, 1, 1];
    const threshold = 3;

    let signers;
    const message = '0x6162636566676869';

    before(async () => {
        await bls254.init();

        signers = weights.map((w, i) => {
            const key = bls254.newKeyPair(); // pubkey \in G2, secret
            const pkG1 = bls254.g1Mul(key.secret, bls254.g1());

            return {
                index: i,
                weight: w,
                sk: key.secret,
                pkG1: pkG1,
                pkG2: key.pubkey,
            };
        });

        // signers.forEach(s => console.log(s.index, s.weight, formatG1(convertG1(s.pkG1))));

        const WeightedMultiSig = await hre.ethers.getContractFactory('WeightedMultiSig');
        wms = await WeightedMultiSig.deploy(threshold, signers.map(s => convertG1(s.pkG1)), weights);
        await wms.deployed();
    });


    it("should verify maximum quorum", async () => {
        assert(await wms.callStatic.isQuorum('0x0f')); // 1111
    });

    it("should pass 3 of 4", async () => {
        assert(await wms.callStatic.isQuorum('0x07')); // 0111
        assert(await wms.callStatic.isQuorum('0x0b')); // 1011
        assert(await wms.callStatic.isQuorum('0x0d')); // 1101
        assert(await wms.callStatic.isQuorum('0x0e')); // 1110
    });

    it("should fail 2 of 4", async () => {
        assert.equal(await wms.callStatic.isQuorum('0x03'), false); // 0011
        assert.equal(await wms.callStatic.isQuorum('0x09'), false); // 1001
        assert.equal(await wms.callStatic.isQuorum('0x0a'), false); // 1010
        assert.equal(await wms.callStatic.isQuorum('0x0c'), false); // 1100
    });

    it("should check agg pk correctly", async () => {
        const bits = '0x07';
        const aggPkG2 = bls254.aggreagate(bls254.aggreagate(signers[0].pkG2, signers[1].pkG2), signers[2].pkG2);

        assert(await wms.callStatic.checkAggPk(bits, convertG2(aggPkG2)));
    });

    it("should check agg sig correctly", async () => {
        const bits = '0x07'; // 00000111
        const aggPkG2 = bls254.aggreagate(bls254.aggreagate(signers[0].pkG2, signers[1].pkG2), signers[2].pkG2);

        const sigs = signers.map(s => bls254.sign(message, s.sk));
        const aggSig = bls254.aggreagate(bls254.aggreagate(sigs[0].signature, sigs[1].signature), sigs[2].signature);

        assert(await wms.callStatic.checkSig(bits, message, convertG1(aggSig), convertG2(aggPkG2)));
    });
});
