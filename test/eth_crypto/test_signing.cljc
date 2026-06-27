(ns eth-crypto.test-signing
  "VERIFICATION GATE (mandatory) for the secp256k1 SIGNING side: RFC-6979
  deterministic ECDSA + EIP-2 low-s + EIP-155 legacy transaction signing.
  Asserts the canonical EIP-155 spec example (the worked example in EIP-155
  itself) byte-for-byte: the signing hash, v/r/s, and the full raw signed tx.
  Plus a sign→ecrecover roundtrip and an address-from-privkey known vector.
  If this fails, the signing crypto must NOT ship."
  (:require [clojure.test :refer [deftest is testing]]
            [eth-crypto.core :as eth]))

;; ── EIP-155 canonical worked example ──
;; privkey 0x4646...46, the tx below, chainId 1.
(def eip155-privkey
  (eth/hex->bytes "0x4646464646464646464646464646464646464646464646464646464646464646"))

(def eip155-tx
  {:nonce     9
   :gas-price 20000000000
   :gas       21000
   :to        "0x3535353535353535353535353535353535353535"
   :value     1000000000000000000
   :data      "0x"
   :chain-id  1})

(deftest eip155-signing-hash
  (testing "keccak of RLP([nonce,gasPrice,gas,to,value,data,chainId,0,0])"
    (let [sighash (eth/keccak256
                   (eth/rlp-encode
                    [(#'eth/->num-bytes 9)
                     (#'eth/->num-bytes 20000000000)
                     (#'eth/->num-bytes 21000)
                     (eth/hex->bytes "0x3535353535353535353535353535353535353535")
                     (#'eth/->num-bytes 1000000000000000000)
                     (byte-array 0)
                     (#'eth/->num-bytes 1)
                     (byte-array 0)
                     (byte-array 0)]))]
      (is (= "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
             (str "0x" (eth/bytes->hex sighash)))))))

(deftest eip155-signature-values
  (testing "RFC-6979 deterministic v/r/s for the EIP-155 example"
    (let [sighash (eth/hex->bytes
                   "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
          {:keys [r s recovery-id]} (eth/secp256k1-sign eip155-privkey sighash)
          v (+ recovery-id (* 2 1) 35)]
      (is (= 37 v) "v = recovery-id + chainId*2 + 35")
      (is (= "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
             (eth/bytes->hex (#'eth/uint->minimal r))) "r")
      (is (= "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
             (eth/bytes->hex (#'eth/uint->minimal s))) "s"))))

(deftest eip155-raw-signed-tx
  (testing "full raw signed tx matches EIP-155 spec byte-for-byte"
    (is (= "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
           (eth/sign-tx-legacy eip155-tx eip155-privkey)))))

;; ── address from private key (known vector) ──
(deftest address-of-privkey-vector
  (is (= "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
         (eth/address-of-privkey
          (eth/hex->bytes
           "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")))))

;; ── sign → ecrecover roundtrip ──
(deftest sign-ecrecover-roundtrip
  (testing "ecrecover of our own signature recovers the signer address"
    (let [digest (eth/keccak256 (eth/utf8 "the founder authorized self-implementing clj"))
          {:keys [r s recovery-id]} (eth/secp256k1-sign eip155-privkey digest)
          sig (byte-array 65)]
      (System/arraycopy (#'eth/pad-left-32 (#'eth/uint->minimal r)) 0 sig 0 32)
      (System/arraycopy (#'eth/pad-left-32 (#'eth/uint->minimal s)) 0 sig 32 32)
      (aset-byte sig 64 (unchecked-byte (+ recovery-id 27)))
      (is (= (eth/address-of-privkey eip155-privkey)
             (eth/ecrecover-checksum digest sig))))))
