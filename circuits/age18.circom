pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

template Age18() {
    signal input birthDate;
    signal input salt;
    signal input commitment;
    signal input cutoff;
    signal input challengeHash;
    signal output requestTag;

    component birthDateBits = Num2Bits(32);
    birthDateBits.in <== birthDate;

    component cutoffBits = Num2Bits(32);
    cutoffBits.in <== cutoff;

    component challengeBits = Num2Bits(248);
    challengeBits.in <== challengeHash;

    component ageCheck = LessEqThan(32);
    ageCheck.in[0] <== birthDate;
    ageCheck.in[1] <== cutoff;
    ageCheck.out === 1;

    component credentialCommitment = Poseidon(2);
    credentialCommitment.inputs[0] <== birthDate;
    credentialCommitment.inputs[1] <== salt;
    credentialCommitment.out === commitment;

    component tag = Poseidon(2);
    tag.inputs[0] <== challengeHash;
    tag.inputs[1] <== commitment;
    requestTag <== tag.out;
}

component main {public [commitment, cutoff, challengeHash]} = Age18();
