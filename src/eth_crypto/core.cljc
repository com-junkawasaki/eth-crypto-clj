(ns eth-crypto.core
  "Standalone, dependency-free Ethereum crypto primitives (Keccak-256, EIP-55,
  EIP-712 typed-data, secp256k1 ecrecover). Pure Clojure (only clojure.* +
  java.math.BigInteger) so it runs unchanged under babashka AND the JVM —
  lib-ready for extraction into com-junkawasaki/eth-crypto-clj.

  IMPLEMENTATION NOTE — why pure Clojure, not BouncyCastle:
  babashka is a GraalVM *native image*. It can only use Java classes baked into
  the bb binary; arbitrary jars on the classpath are NOT loadable at runtime
  (`java.security` exposes SHA3-256 but NOT Keccak-256, and any
  `org.bouncycastle.*` import throws ClassNotFoundException). So Keccak-256 is
  implemented here as the Keccak-f[1600] permutation, and secp256k1 ecrecover via
  `java.math.BigInteger` (which IS available). Verified against the canonical
  EIP-712 'Ether Mail' spec vector — see test/eth_crypto/test_eth_crypto.cljc.

  Public API:
    keccak256          bytes -> 32 bytes (Keccak-256, NOT SHA3-256)
    eip55-checksum     20-byte addr (or hex) -> EIP-55 mixed-case 0x string
    type-hash          types primary -> 32-byte keccak of encodeType
    encode-data        types primary data -> ABI-encoded struct bytes
    hash-struct        types primary data -> 32-byte hashStruct
    domain-separator   domain-map -> 32-byte EIP712Domain hashStruct
    eip712-digest      domain types primary message -> 32-byte signing digest
    ecrecover          32-byte digest + 65-byte sig{r,s,v} -> 20-byte address
    private->public    32-byte privkey -> 64-byte uncompressed pubkey (no 0x04)
    address-of-privkey 32-byte privkey -> EIP-55 0x… address
    secp256k1-sign     privkey + digest -> {:r :s :recovery-id} (RFC 6979, low-s)
    rlp-encode         byte-string / nested list -> canonical Ethereum RLP bytes
    sign-tx-legacy     tx + privkey -> 0x… raw signed EIP-155 legacy transaction"
  (:require [clojure.string :as str]))

;; ─── hex / byte helpers ──────────────────────────────────────────────

(defn strip0x ^String [^String s]
  (if (str/starts-with? s "0x") (subs s 2) s))

(defn hex->bytes ^"[B" [s]
  (let [s (strip0x s)
        n (quot (count s) 2)
        out (byte-array n)]
    (dotimes [i n]
      (aset-byte out i (unchecked-byte (Integer/parseInt (subs s (* 2 i) (+ 2 (* 2 i))) 16))))
    out))

(defn bytes->hex ^String [^"[B" b]
  (let [sb (StringBuilder.)]
    (dotimes [i (alength b)]
      (.append sb (format "%02x" (bit-and (aget b i) 0xff))))
    (.toString sb)))

(defn utf8 ^"[B" [^String s] (.getBytes s "UTF-8"))

(defn- ^"[B" pad-left-32 [^"[B" b]
  (let [n (alength b) out (byte-array 32)]
    (System/arraycopy b 0 out (- 32 n) n)
    out))

(defn- ^"[B" concat-bytes [arrays]
  (let [total (reduce (fn [^long n ^"[B" a] (+ n (alength a))) 0 arrays)
        out (byte-array total)]
    (loop [off 0 ps arrays]
      (if (seq ps)
        (let [^"[B" p (first ps)]
          (System/arraycopy p 0 out off (alength p))
          (recur (+ off (alength p)) (rest ps)))
        out))))

;; ─── Keccak-256 (Keccak-f[1600], Ethereum padding — NOT SHA3) ─────────

(def ^:private ^"[J" RC
  (long-array
   [0x0000000000000001 0x0000000000008082 (unchecked-long 0x800000000000808A)
    (unchecked-long 0x8000000080008000) 0x000000000000808B 0x0000000080000001
    (unchecked-long 0x8000000080008081) (unchecked-long 0x8000000000008009)
    0x000000000000008A 0x0000000000000088 0x0000000080008009 0x000000008000000A
    0x000000008000808B (unchecked-long 0x800000000000008B) (unchecked-long 0x8000000000008089)
    (unchecked-long 0x8000000000008003) (unchecked-long 0x8000000000008002)
    (unchecked-long 0x8000000000000080) 0x000000000000800A (unchecked-long 0x800000008000000A)
    (unchecked-long 0x8000000080008081) (unchecked-long 0x8000000000008080)
    0x0000000080000001 (unchecked-long 0x8000000080008008)]))

;; rotation offsets r[x][y] at flat index x+5y
(def ^:private ^"[I" ROT
  (int-array
   [0 1 62 28 27
    36 44 6 55 20
    3 10 43 25 39
    41 45 15 21 8
    18 2 61 56 14]))

(defn- rotl64 [^long x ^long n]
  (if (zero? n) x
      (bit-or (bit-shift-left x n) (unsigned-bit-shift-right x (- 64 n)))))

(defn- keccak-f! [^"[J" a]
  (let [bc (long-array 5)
        tmp (long-array 25)]
    (dotimes [round 24]
      ;; θ
      (dotimes [x 5]
        (aset bc x (bit-xor (aget a x) (aget a (+ x 5)) (aget a (+ x 10))
                            (aget a (+ x 15)) (aget a (+ x 20)))))
      (dotimes [x 5]
        (let [d (bit-xor (aget bc (mod (+ x 4) 5))
                         (rotl64 (aget bc (mod (+ x 1) 5)) 1))]
          (dotimes [y 5]
            (aset a (+ x (* 5 y)) (bit-xor (aget a (+ x (* 5 y))) d)))))
      ;; ρ + π : tmp[y, 2x+3y] = rot(a[x,y], r[x,y])
      (dotimes [x 5]
        (dotimes [y 5]
          (let [i (+ x (* 5 y))
                j (+ y (* 5 (mod (+ (* 2 x) (* 3 y)) 5)))]
            (aset tmp j (rotl64 (aget a i) (aget ROT i))))))
      ;; χ
      (dotimes [y 5]
        (dotimes [x 5]
          (aset a (+ x (* 5 y))
                (bit-xor (aget tmp (+ x (* 5 y)))
                         (bit-and (bit-not (aget tmp (+ (mod (+ x 1) 5) (* 5 y))))
                                  (aget tmp (+ (mod (+ x 2) 5) (* 5 y))))))))
      ;; ι
      (aset a 0 (bit-xor (aget a 0) (aget RC round))))
    a))

(defn keccak256 ^"[B" [^"[B" input]
  (let [rate 136                          ; 1088 bits = 256-bit output
        a (long-array 25)
        len (alength input)
        padlen (- rate (mod len rate))
        total (+ len padlen)
        msg (byte-array total)]
    (System/arraycopy input 0 msg 0 len)
    ;; original-Keccak pad10*1: first pad byte 0x01, last byte |= 0x80
    (aset-byte msg len (unchecked-byte 0x01))
    (aset-byte msg (dec total)
               (unchecked-byte (bit-or (bit-and (aget msg (dec total)) 0xff) 0x80)))
    (loop [off 0]
      (when (< off total)
        (dotimes [i (quot rate 8)]
          (let [base (+ off (* i 8))
                lane (loop [k 0 acc 0]
                       (if (< k 8)
                         (recur (inc k)
                                (bit-or acc (bit-shift-left
                                             (bit-and (aget msg (+ base k)) 0xff) (* 8 k))))
                         acc))]
            (aset a i (bit-xor (aget a i) lane))))
        (keccak-f! a)
        (recur (+ off rate))))
    (let [out (byte-array 32)]
      (dotimes [i 4]
        (let [lane (aget a i)]
          (dotimes [k 8]
            (aset-byte out (+ (* i 8) k)
                       (unchecked-byte (bit-and (unsigned-bit-shift-right lane (* 8 k)) 0xff))))))
      out)))

;; ─── EIP-55 checksum address ─────────────────────────────────────────

(defn eip55-checksum ^String [addr]
  (let [b (if (string? addr) (hex->bytes addr) addr)
        lower (bytes->hex b)              ; 40 lowercase hex chars
        hash (bytes->hex (keccak256 (utf8 lower)))
        sb (StringBuilder. "0x")]
    (dotimes [i 40]
      (let [c (.charAt lower i)
            h (Character/digit (.charAt hash i) 16)]
        (.append sb (if (and (Character/isLetter c) (>= h 8))
                      (Character/toUpperCase c) c))))
    (.toString sb)))

;; ─── EIP-712 typed-data encoder ──────────────────────────────────────
;; types : {typeName(str) [{:name str :type str} ...]}
;; data  : {fieldName(str) value}

(declare encode-data)

(defn- find-deps [types primary]
  (let [seen (atom #{})]
    (letfn [(go [t]
              (when (and (contains? types t) (not (@seen t)))
                (swap! seen conj t)
                (doseq [{:keys [type]} (get types t)]
                  (go (str/replace type #"\[.*\]" "")))))]
      (go primary)
      @seen)))

(defn encode-type ^String [types primary]
  (let [deps (disj (find-deps types primary) primary)
        ordered (cons primary (sort deps))]
    (apply str
           (map (fn [t]
                  (str t "("
                       (str/join "," (map #(str (:type %) " " (:name %)) (get types t)))
                       ")"))
                ordered))))

(defn type-hash ^"[B" [types primary]
  (keccak256 (utf8 (encode-type types primary))))

(defn- ^"[B" uint->32 [v]
  (let [^"[B" ba (.toByteArray (biginteger v))   ; big-endian, two's-complement
        n (alength ba)]
    (cond
      (= n 32) ba
      (< n 32) (pad-left-32 ba)
      :else (let [out (byte-array 32)]              ; n=33 leading sign byte
              (System/arraycopy ba (- n 32) out 0 32) out))))

(defn- ^"[B" encode-field [types type value]
  (cond
    (contains? types type) (keccak256 (encode-data types type value))   ; nested struct
    (= type "string")  (keccak256 (utf8 value))
    (= type "bytes")   (keccak256 (if (string? value) (hex->bytes value) value))
    (= type "bytes32") (pad-left-32 (if (string? value) (hex->bytes value) value))
    (= type "address") (pad-left-32 (if (string? value) (hex->bytes value) value))
    (= type "bool")    (uint->32 (if value 1 0))
    (str/starts-with? type "uint") (uint->32 value)
    (str/starts-with? type "int")  (uint->32 value)
    :else (throw (ex-info (str "unsupported EIP-712 type: " type) {:type type}))))

(defn encode-data ^"[B" [types primary data]
  (concat-bytes
   (cons (type-hash types primary)
         (map (fn [{:keys [name type]}] (encode-field types type (get data name)))
              (get types primary)))))

(defn hash-struct ^"[B" [types primary data]
  (keccak256 (encode-data types primary data)))

(def ^:private EIP712-DOMAIN-TYPE
  {"EIP712Domain" [{:name "name" :type "string"}
                   {:name "version" :type "string"}
                   {:name "chainId" :type "uint256"}
                   {:name "verifyingContract" :type "address"}]})

(defn domain-separator ^"[B" [domain]
  (hash-struct EIP712-DOMAIN-TYPE "EIP712Domain" domain))

(defn eip712-digest ^"[B" [domain types primary message]
  (let [ds (domain-separator domain)
        hs (hash-struct types primary message)
        pre (byte-array 66)]
    (aset-byte pre 0 (unchecked-byte 0x19))
    (aset-byte pre 1 (unchecked-byte 0x01))
    (System/arraycopy ds 0 pre 2 32)
    (System/arraycopy hs 0 pre 34 32)
    (keccak256 pre)))

;; ─── secp256k1 ecrecover (via BigInteger) ────────────────────────────

(def ^:private ^BigInteger SECP-P
  (BigInteger. "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F" 16))
(def ^:private ^BigInteger SECP-N
  (BigInteger. "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141" 16))
(def ^:private ^BigInteger SECP-B (BigInteger/valueOf 7))
(def ^:private ^BigInteger SECP-GX
  (BigInteger. "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" 16))
(def ^:private ^BigInteger SECP-GY
  (BigInteger. "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8" 16))
(def ^:private G [SECP-GX SECP-GY])

;; affine point [x y] (BigInteger), nil = point at infinity. y² = x³ + 7 over Fp.
(defn- pt-add [p1 p2]
  (cond
    (nil? p1) p2
    (nil? p2) p1
    :else
    (let [[x1 y1] p1 [x2 y2] p2]
      (if (and (= x1 x2) (= (.mod (.add ^BigInteger y1 ^BigInteger y2) SECP-P) BigInteger/ZERO))
        nil                                          ; P + (−P) = ∞
        (let [m (if (and (= x1 x2) (= y1 y2))
                  (.mod (.multiply (.multiply (BigInteger/valueOf 3) (.multiply x1 x1))
                                   (.modInverse (.multiply (BigInteger/valueOf 2) y1) SECP-P)) SECP-P)
                  (.mod (.multiply (.subtract y2 y1)
                                   (.modInverse (.subtract x2 x1) SECP-P)) SECP-P))
              x3 (.mod (.subtract (.subtract (.multiply m m) x1) x2) SECP-P)
              y3 (.mod (.subtract (.multiply m (.subtract x1 x3)) y1) SECP-P)]
          [x3 y3])))))

(defn- pt-mul [^BigInteger k pt]
  (loop [k k acc nil base pt]
    (if (= k BigInteger/ZERO)
      acc
      (recur (.shiftRight k 1)
             (if (.testBit k 0) (pt-add acc base) acc)
             (pt-add base base)))))

(defn- ^BigInteger mod-sqrt
  "√a mod p for p ≡ 3 (mod 4) (secp256k1 prime)."
  [^BigInteger a]
  (.modPow a (.divide (.add SECP-P BigInteger/ONE) (BigInteger/valueOf 4)) SECP-P))

(defn- decompress [^BigInteger x y-odd?]
  (let [y2 (.mod (.add (.modPow x (BigInteger/valueOf 3) SECP-P) SECP-B) SECP-P)
        y (mod-sqrt y2)
        y (if (= (.testBit y 0) (boolean y-odd?)) y (.subtract SECP-P y))]
    [x y]))

(defn ecrecover
  "Recover the signer's 20-byte address from a 32-byte EIP-712 `digest` and a
  65-byte `sig` (r‖s‖v). v ∈ {27,28} (or {0,1}); recovery id = v mod 27."
  ^"[B" [^"[B" digest ^"[B" sig]
  (let [r (BigInteger. 1 (java.util.Arrays/copyOfRange sig 0 32))
        s (BigInteger. 1 (java.util.Arrays/copyOfRange sig 32 64))
        v (bit-and (aget sig 64) 0xff)
        rec-id (if (>= v 27) (- v 27) v)
        e (BigInteger. 1 digest)
        x (.add r (.multiply SECP-N (BigInteger/valueOf (long (bit-shift-right rec-id 1)))))
        R (decompress x (odd? (bit-and rec-id 1)))
        r-inv (.modInverse r SECP-N)
        ;; Q = r⁻¹ (sR − eG)
        sR (pt-mul s R)
        eG (pt-mul e G)
        neg-eG [(first eG) (.mod (.negate ^BigInteger (second eG)) SECP-P)]
        Q (pt-mul r-inv (pt-add sR neg-eG))
        [qx qy] Q
        pub (byte-array 64)]
    (System/arraycopy (pad-left-32 (let [^"[B" b (.toByteArray ^BigInteger qx)]
                                     (if (> (alength b) 32)
                                       (java.util.Arrays/copyOfRange b (- (alength b) 32) (alength b)) b)))
                      0 pub 0 32)
    (System/arraycopy (pad-left-32 (let [^"[B" b (.toByteArray ^BigInteger qy)]
                                     (if (> (alength b) 32)
                                       (java.util.Arrays/copyOfRange b (- (alength b) 32) (alength b)) b)))
                      0 pub 32 32)
    (java.util.Arrays/copyOfRange (keccak256 pub) 12 32)))

(defn ecrecover-checksum
  "ecrecover then EIP-55 checksum the recovered address."
  ^String [^"[B" digest ^"[B" sig]
  (eip55-checksum (ecrecover digest sig)))

;; ─── public key / address from private key ───────────────────────────

(defn private->public
  "secp256k1 public key from a 32-byte private key. Returns the 64-byte
  uncompressed point X‖Y (WITHOUT the 0x04 prefix), i.e. keccak256 of this is
  the address preimage."
  ^"[B" [^"[B" privkey]
  (let [d (BigInteger. 1 privkey)
        [qx qy] (pt-mul d G)
        pub (byte-array 64)]
    (System/arraycopy (uint->32 qx) 0 pub 0 32)
    (System/arraycopy (uint->32 qy) 0 pub 32 32)
    pub))

(defn address-of-privkey
  "EIP-55 checksummed 0x… address controlled by a 32-byte private key:
  last 20 bytes of keccak256(uncompressed-pubkey-without-04-prefix)."
  ^String [^"[B" privkey]
  (eip55-checksum
   (java.util.Arrays/copyOfRange (keccak256 (private->public privkey)) 12 32)))

;; ─── deterministic ECDSA signing (RFC 6979 + EIP-2 low-s) ────────────

(defn- ^"[B" hmac-sha256 [^"[B" key ^"[B" data]
  (let [mac (javax.crypto.Mac/getInstance "HmacSHA256")]
    (.init mac (javax.crypto.spec.SecretKeySpec. key "HmacSHA256"))
    (.doFinal mac data)))

(def ^:private ^BigInteger SECP-N-HALF (.shiftRight SECP-N 1))

(defn secp256k1-sign
  "Deterministic ECDSA signature over secp256k1 of a 32-byte `digest` with a
  32-byte `privkey`, using an RFC 6979 (HMAC-SHA256) nonce and EIP-2 low-s
  normalization (s ≤ n/2). Returns {:r BigInteger :s BigInteger :recovery-id 0|1}.
  Pure java.math.BigInteger + javax.crypto HMAC (both available in babashka)."
  [^"[B" privkey ^"[B" digest]
  (let [n SECP-N
        z (BigInteger. 1 digest)               ; bits2int(h1), 256-bit
        d (BigInteger. 1 privkey)
        hsize 32
        x-oct (uint->32 d)                     ; int2octets(x)
        h-oct (uint->32 (.mod z n))            ; bits2octets(h1)
        b00 (byte-array 1)                     ; single 0x00
        b01 (byte-array [(unchecked-byte 1)])  ; single 0x01
        ;; RFC 6979 3.2 steps b–g
        V0 (byte-array hsize (unchecked-byte 1))
        K0 (byte-array hsize (unchecked-byte 0))
        K1 (hmac-sha256 K0 (concat-bytes [V0 b00 x-oct h-oct]))
        V1 (hmac-sha256 K1 V0)
        K2 (hmac-sha256 K1 (concat-bytes [V1 b01 x-oct h-oct]))
        V2 (hmac-sha256 K2 V1)]
    ;; step h: HMAC-SHA256 output is 32 bytes = qlen/8, so one block == T
    (loop [K K2 V V2]
      (let [T (hmac-sha256 K V)
            k (BigInteger. 1 T)
            result
            (when (and (>= (.signum k) 1) (< (.compareTo k n) 0))
              (let [[rx ry] (pt-mul k G)
                    r (.mod rx n)]
                (when-not (= r BigInteger/ZERO)
                  (let [s (.mod (.multiply (.modInverse k n)
                                           (.add z (.multiply r d))) n)]
                    (when-not (= s BigInteger/ZERO)
                      (let [rec (bit-or (if (.testBit ^BigInteger ry 0) 1 0)
                                        (if (>= (.compareTo rx n) 0) 2 0))]
                        (if (> (.compareTo s SECP-N-HALF) 0)
                          {:r r :s (.subtract n s) :recovery-id (bit-xor rec 1)}
                          {:r r :s s :recovery-id rec})))))))]
        (or result
            (let [K' (hmac-sha256 K (concat-bytes [T b00]))
                  V' (hmac-sha256 K' T)]
              (recur K' V')))))))

;; ─── RLP encoding (canonical Ethereum) ───────────────────────────────

(defn- ^"[B" uint->minimal
  "Minimal big-endian byte-string of a non-negative integer (0 → empty)."
  [v]
  (let [bi (biginteger v)]
    (if (= bi BigInteger/ZERO)
      (byte-array 0)
      (let [^"[B" b (.toByteArray bi)]
        (if (and (> (alength b) 1) (zero? (aget b 0)))
          (java.util.Arrays/copyOfRange b 1 (alength b))   ; strip sign byte
          b)))))

(defn- ^"[B" rlp-prefix
  "RLP length prefix. `offset` is 0x80 (byte-string) or 0xc0 (list)."
  [^long offset ^long len]
  (if (< len 56)
    (byte-array [(unchecked-byte (+ offset len))])
    (let [len-bytes (uint->minimal len)]
      (concat-bytes [(byte-array [(unchecked-byte (+ offset 55 (alength len-bytes)))])
                     len-bytes]))))

(defn rlp-encode
  "Canonical recursive RLP. `item` is a byte-array (byte-string) or a sequential
  collection of items (list). Returns the RLP bytes."
  ^"[B" [item]
  (if (sequential? item)
    (let [payload (concat-bytes (map rlp-encode item))]
      (concat-bytes [(rlp-prefix 0xc0 (alength payload)) payload]))
    (let [^"[B" b item
          n (alength b)]
      (if (and (= n 1) (< (bit-and (aget b 0) 0xff) 0x80))
        b                                              ; single byte < 0x80 → itself
        (concat-bytes [(rlp-prefix 0x80 n) b])))))

;; ─── EIP-155 legacy transaction signing ──────────────────────────────

(defn- ^"[B" ->num-bytes
  "Coerce an int / 0x-hex string / bytes numeric field to its minimal RLP
  big-endian byte-string."
  [v]
  (uint->minimal
   (cond
     (nil? v)     BigInteger/ZERO
     (number? v)  (biginteger v)
     (string? v)  (let [s (strip0x v)] (if (empty? s) BigInteger/ZERO (BigInteger. s 16)))
     :else        (BigInteger. 1 ^"[B" v))))

(defn- ^"[B" ->byte-str
  "Coerce a 0x-hex string / bytes / nil opaque field (address, data) to bytes."
  [v]
  (cond
    (nil? v)    (byte-array 0)
    (string? v) (hex->bytes v)
    :else       v))

(defn sign-tx-legacy
  "Sign an EIP-155 legacy transaction. `tx` is a map with keys
  :nonce :gas-price :gas :to :value :data :chain-id (each an int, 0x-hex string,
  or bytes; :to/:data are opaque byte-strings, the rest are numbers). Returns the
  0x… RLP-encoded raw signed transaction hex ready for eth_sendRawTransaction."
  ^String [tx ^"[B" privkey]
  (let [{:keys [nonce gas-price gas to value data chain-id]} tx
        nonce-b (->num-bytes nonce)
        gp-b    (->num-bytes gas-price)
        gas-b   (->num-bytes gas)
        to-b    (->byte-str to)
        value-b (->num-bytes value)
        data-b  (->byte-str data)
        chain-b (->num-bytes chain-id)
        empty-b (byte-array 0)
        sighash (keccak256
                 (rlp-encode [nonce-b gp-b gas-b to-b value-b data-b chain-b empty-b empty-b]))
        {:keys [r s recovery-id]} (secp256k1-sign privkey sighash)
        cid (BigInteger. 1 (let [b chain-b] (if (zero? (alength b)) (byte-array 1) b)))
        v (.add (.add (BigInteger/valueOf recovery-id)
                      (.multiply (BigInteger/valueOf 2) cid))
                (BigInteger/valueOf 35))
        raw (rlp-encode [nonce-b gp-b gas-b to-b value-b data-b
                         (->num-bytes v) (->num-bytes r) (->num-bytes s)])]
    (str "0x" (bytes->hex raw))))
