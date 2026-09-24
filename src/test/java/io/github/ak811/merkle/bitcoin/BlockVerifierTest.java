package io.github.ak811.merkle.bitcoin;

import io.github.ak811.merkle.TestData;
import io.github.ak811.merkle.concurrent.WorkerPool;
import io.github.ak811.merkle.crypto.Hash32;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BlockVerifierTest {

    private static WorkerPool pool;
    private static BlockVerifier verifier;

    @BeforeAll
    static void start() {
        pool = new WorkerPool(4);
        verifier = new BlockVerifier(pool);
    }

    @AfterAll
    static void stop() {
        pool.close();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "genesis, 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, "
                    + "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b, 1, 0, NOT_APPLICABLE",
            "testnet-3kib, 000000005ee8f3674748276fdc56a0202714d94bde87cd943195cc84cf57caf0, "
                    + "d341de2b601a52ae3eb4f350b927ce5e6ef4f9e32839b59ae611d94153afbd0e, 10, 0, NOT_APPLICABLE",
            "testnet-32kib, 000000000c9f25eb2565f81cdbe98aa692ccda81a3532cea1301a284b8f0cc0c, "
                    + "70f719e112deef26cc9c955606e3c07e09441885d69ddd947ae66f4697f4400c, 103, 0, NOT_APPLICABLE",
            "mainnet-542213-segwit, 000000000000000000143a2c56c0214236dadfd30df41d4a0345492ad6d861ec, "
                    + "64a8b69cb7100430aec35825d54a48f4434f3db52dff8a02709aee3a659b5e13, 4, 2, VALID"})
    void verifiesRealBitcoinBlocks(String name, String blockHash, String merkleRoot, int txCount, int segwit,
                                   WitnessCheck.Status witness) throws BlockFormatException {
        BlockReport report = verifier.verify(Block.parse(TestData.block(name)));

        assertEquals(Hash32.fromDisplayHex(blockHash), report.header().hash());
        assertEquals(Hash32.fromDisplayHex(merkleRoot), report.header().merkleRoot());
        assertEquals(report.header().merkleRoot(), report.computedMerkleRoot());
        assertEquals(txCount, report.txids().size());
        assertEquals(segwit, report.segwitTransactions());
        assertEquals(witness, report.witness().status());
        assertFalse(report.mutated());
        assertTrue(report.header().hasValidProofOfWork());
        assertTrue(report.valid());
    }

    @Test
    void genesisCoinbaseTxidEqualsTheMerkleRoot() throws BlockFormatException {
        BlockReport report = verifier.verify(Block.parse(TestData.block("genesis")));
        assertEquals(report.header().merkleRoot(), report.txids().get(0));
    }

    @Test
    void alteringATransactionBreaksTheMerkleRoot() throws BlockFormatException {
        byte[] data = TestData.block("testnet-3kib");
        Block original = Block.parse(data);
        TransactionLayout tx = original.transactions().get(5);
        byte[] tampered = data.clone();
        tampered[tx.end() - 1] ^= 0x01; // flip a bit of the lock time

        BlockReport report = verifier.verify(Block.parse(tampered));

        assertFalse(report.merkleRootMatches());
        assertFalse(report.valid());
    }

    @Test
    void alteringTheNonceBreaksProofOfWork() throws BlockFormatException {
        byte[] tampered = TestData.block("testnet-3kib");
        tampered[76] ^= 0x01; // the nonce occupies header bytes 76..79

        BlockReport report = verifier.verify(Block.parse(tampered));

        assertTrue(report.merkleRootMatches());
        assertFalse(report.header().hasValidProofOfWork());
        assertFalse(report.valid());
    }

    @Test
    void alteringWitnessDataKeepsTheTxidButBreaksTheWitnessCommitment() throws BlockFormatException {
        byte[] data = TestData.block("mainnet-542213-segwit");
        Block original = Block.parse(data);
        TransactionLayout tx = original.transactions().stream()
                .skip(1).filter(TransactionLayout::segwit).findFirst().orElseThrow();
        byte[] tampered = data.clone();
        tampered[tx.witnessEnd() - 1] ^= 0x01; // last byte of the last witness item

        BlockReport before = verifier.verify(original);
        BlockReport after = verifier.verify(Block.parse(tampered));

        // Witness data is excluded from txids, so the header's Merkle root still matches...
        assertEquals(before.txids(), after.txids());
        assertTrue(after.merkleRootMatches());
        // ...but the wtxid changes, so the coinbase's witness commitment no longer does.
        assertEquals(WitnessCheck.Status.INVALID, after.witness().status());
        assertFalse(after.valid());
    }

    @Test
    void rejectsMalformedBlocks() {
        byte[] data = TestData.block("testnet-3kib");
        assertThrows(BlockFormatException.class, () -> Block.parse(Arrays.copyOf(data, 79)));
        assertThrows(BlockFormatException.class, () -> Block.parse(Arrays.copyOf(data, data.length - 1)));
        assertThrows(BlockFormatException.class, () -> Block.parse(Arrays.copyOf(data, data.length + 1)));

        byte[] noTransactions = Arrays.copyOf(data, 81);
        noTransactions[80] = 0;
        assertThrows(BlockFormatException.class, () -> Block.parse(noTransactions));

        byte[] nonCanonical = Arrays.copyOf(data, 84);
        nonCanonical[80] = (byte) 0xfd; // 0xfd prefix encoding a value below 0xfd
        nonCanonical[81] = 10;
        nonCanonical[82] = 0;
        BlockFormatException e = assertThrows(BlockFormatException.class, () -> Block.parse(nonCanonical));
        assertTrue(e.getMessage().contains("non-canonical"), e.getMessage());
    }

    @Test
    void decodesCompactTargets() throws BlockFormatException {
        BlockHeader header = Block.parse(TestData.block("genesis")).header();
        assertEquals(java.math.BigInteger.valueOf(0xffff).shiftLeft(208), header.target().orElseThrow());

        Hash32 z = Hash32.ZERO;
        assertTrue(new BlockHeader(1, z, z, 0, 0x04923456L, 0, z).target().isEmpty(), "negative");
        assertTrue(new BlockHeader(1, z, z, 0, 0xff123456L, 0, z).target().isEmpty(), "overflow");
        assertTrue(new BlockHeader(1, z, z, 0, 0x01003456L, 0, z).target().isEmpty(), "zero");
        assertEquals(java.math.BigInteger.valueOf(0x12), new BlockHeader(1, z, z, 0, 0x01120000L, 0, z).target().orElseThrow());
    }
}
