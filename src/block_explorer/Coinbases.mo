// Canonical coinbase byte store.
//
// Layout: one stable Region holding the raw coinbase bytes of every
// canonical block, in canonical height order, back-to-back with no
// framing. The end-offset of each block's coinbase lives inline in that
// block's HeaderValue (bytes 32..36 — see HeaderValue.mo). The length of
// block h's coinbase is therefore `coinbaseEnd(h) - coinbaseEnd(h - 1)`,
// with `coinbaseEnd(-1) := 0` by convention, so no length prefix is
// stored in the region itself.
//
// Properties:
//   * Deterministic — bytes in the region are a function of
//     (canonical height, coinbase bytes), independent of upload order.
//     Two canisters that ingested the same chain history (whatever the
//     interleaving of push_body / backfill / fork promotions) end up
//     with byte-identical region contents.
//   * Fork coinbases are NOT stored here. Fork bodies on the heap carry
//     their coinbase as `?Blob`. Promotion appends to the region;
//     demotion truncates the region tail and moves the demoted bytes
//     onto the heap-side fork body.
//   * Grow-only during normal operation, with the single exception of a
//     tail truncation on reorg (which just rewinds `size`; the region's
//     page allocation itself is never shrunk, since `Region.grow` is
//     one-way).
//
// Access: this module exposes helpers that take a `Store` (opaque type
// alias for `Region.Region`) and a `size : Nat64` passed by the caller
// (Chain's `coinbasesRegionSize` var). Keeping the size out of the Region
// frees us from having to probe `Region.size` (page count, not byte count)
// on every append. Keeping the Region type and constructor behind this
// module means callers (Chain, Migration) never touch `mo:core/Region`
// directly.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";

module {

  // Opaque alias for the backing stable region. Chain/Migration refer to
  // this type (and `newStore()` below) so neither has to import
  // `mo:core/Region` directly.
  public type Store = Region.Region;

  public func newStore() : Store = Region.new();

  // One region page = 64 KiB.
  let PAGE : Nat64 = 65536;

  // Grow `region` by whole pages until it can hold at least `size` bytes.
  // Idempotent / cheap when the region is already large enough. Returns
  // nothing — the caller keeps its own `size` cursor; this just extends
  // the allocation.
  public func ensureCapacity(region : Store, size : Nat64) {
    let havePages = region.size();
    let needPages = (size +% (PAGE -% 1)) / PAGE;
    if (needPages > havePages) {
      let grow = needPages -% havePages;
      let got = region.grow(grow);
      if (got == 0xffff_ffff_ffff_ffff) {
        Runtime.trap("Coinbases: region grow failed (" # debug_show grow # " pages)");
      };
    };
  };

  // Append `coinbase` to the end of the region. Returns the new byte
  // size (= end-offset of the just-written entry). Caller updates its
  // size cursor from the return value.
  //
  // Grows the region as needed. No framing bytes written — the caller is
  // responsible for recording the end-offset in the per-height index
  // (HeaderValue.withCoinbaseEnd).
  public func append(region : Store, oldSize : Nat64, coinbase : Blob) : Nat64 {
    let n = coinbase.size().toNat64();
    let newSize = oldSize +% n;
    ensureCapacity(region, newSize);
    region.storeBlob(oldSize, coinbase);
    newSize;
  };

  // Read the coinbase at byte range `[start, end)` from the region. The
  // caller derives `start` from the previous block's `coinbaseEnd` (or
  // `0` for height 0) and `end` from the current block's `coinbaseEnd`.
  // Traps on an inconsistent range (end < start, or end past the region
  // size) — these would indicate corrupted index state.
  public func load(region : Store, start : Nat32, end : Nat32) : Blob {
    if (end < start) Runtime.trap("Coinbases: load with end < start");
    let len = (end -% start) : Nat32;
    region.loadBlob(start.toNat64(), len.toNat());
  };

  // ---------------------------------------------------------------------
  // Coinbase scriptSig extraction.
  // ---------------------------------------------------------------------
  //
  // Pulls the miner-controlled bytes out of a raw (witness-stripped)
  // coinbase. The caller has already verified the bytes form a valid
  // coinbase via dSHA at ingest, so the parse never fails on a byte that
  // slipped through — it only traps on fundamentally malformed input,
  // which indicates a bug in whoever stored the bytes.
  //
  // Layout at the input script (witness-stripped Bitcoin tx):
  //
  //   off | bytes
  //  -----+-------------------------------
  //     0 |     4   version (little-endian)
  //     4 |     1   input count varint (always 0x01 for a coinbase)
  //     5 |    32   prev txid (all zeros for a coinbase)
  //    37 |     4   prev vout (0xffffffff — the coinbase sentinel)
  //    41 |   1-3   script_len varint (BIP34 caps at 100 bytes, so always 1)
  //    42 |  2-100  scriptSig (the "coinbase field" — miner's bytes)
  //       |     4   sequence (not read)
  //       |   …     outputs / locktime (not read)

  // Read a 1-byte Bitcoin varint at `off`. BIP34 constrains coinbase
  // scriptSig to <=100 bytes, so this never needs the 2/4/8-byte encodings
  // — a single byte < 0xfd always suffices. For safety we still accept the
  // 0xfd (3-byte) form, which covers up to 65535 bytes.
  func readScriptLenVarint(cb : Blob, off : Nat) : (len : Nat, size : Nat) {
    let b0 = cb[off];
    if (b0 < 0xfd) return (b0.toNat(), 1);
    if (b0 == 0xfd) {
      let lo = cb[off + 1].toNat16();
      let hi = cb[off + 2].toNat16();
      return (((hi << 8) | lo).toNat(), 3);
    };
    Runtime.trap("Coinbases: scriptSig length varint too large (" # debug_show b0 # ")");
  };

  // Extract the coinbase scriptSig from raw bytes. Returns a sub-Blob
  // viewing bytes [42 + varint_size, 42 + varint_size + script_len) of
  // the input.
  //
  // Traps on obviously-malformed input (coinbase shorter than the fixed
  // 42-byte prefix, or script_len that overruns the buffer). The dSHA
  // check at ingest means these never happen for bytes we accepted; this
  // defensiveness is for callers that may pass heap-side fork-body
  // coinbases without re-verifying.
  public func scriptSig(cb : Blob) : Blob {
    if (cb.size() < 42) Runtime.trap("Coinbases: coinbase shorter than 42-byte header prefix");
    let (len, varintSize) = readScriptLenVarint(cb, 41);
    let start = 41 + varintSize;
    if (start + len > cb.size()) Runtime.trap("Coinbases: scriptSig length overruns coinbase bytes");
    // Copy out the scriptSig bytes into a fresh Blob so the caller doesn't
    // retain a reference to the full coinbase.
    let out = Array.tabulate<Nat8>(len, func(i) = cb[start + i]);
    out.toBlob();
  };

  // ---------------------------------------------------------------------
  // Witness commitment.
  // ---------------------------------------------------------------------
  //
  // Whether a raw witness-stripped coinbase has a BIP141 witness
  // commitment output: a scriptPubKey of at least 38 bytes that starts
  // `6a 24 aa 21 a9 ed` (OP_RETURN, push 36, the commitment header). In a
  // block whose coinbase has one (with segwit active), consensus requires
  // the coinbase input's witness to be exactly one 32-byte item, the
  // witness reserved value, which isn't stored: the full serialization of
  // such a coinbase is then not known. Without one, no transaction of the
  // block may carry witness data, so the stripped bytes are the full
  // serialization.
  //
  // Null if `cb` doesn't parse as a transaction with one input that ends
  // exactly at the end of the bytes. Never traps.

  // A CompactSize at `off`: (value, bytes taken), or null past the end.
  func compactSize(cb : Blob, off : Nat) : ?(Nat, Nat) {
    if (off >= cb.size()) return null;
    let b0 = cb[off];
    let k : Nat = if (b0 < 0xfd) return ?(b0.toNat(), 1) else if (b0 == 0xfd) 2 else if (b0 == 0xfe) 4 else 8;
    if (off + 1 + k > cb.size()) return null;
    var v = 0;
    var i = k;
    while (i > 0) { i -= 1; v := v * 256 + cb[off + 1 + i].toNat() };
    ?(v, 1 + k);
  };

  public func witnessCommitted(cb : Blob) : ?Bool {
    let n = cb.size();
    // version (4), one input: prevout (36), scriptSig, sequence (4)
    let ?(inputs, s1) = compactSize(cb, 4) else return null;
    if (inputs != 1) return null;
    let ?(sigLen, s2) = compactSize(cb, 4 + s1 + 36) else return null;
    var off = 4 + s1 + 36 + s2 + sigLen + 4;
    let ?(outputs, s3) = compactSize(cb, off) else return null;
    off += s3;
    var committed = false;
    var o = 0;
    while (o < outputs) {
      off += 8; // value
      let ?(scriptLen, s) = compactSize(cb, off) else return null;
      off += s;
      if (off + scriptLen > n) return null;
      if (
        scriptLen >= 38 and cb[off] == 0x6a and cb[off + 1] == 0x24 and cb[off + 2] == 0xaa and cb[off + 3] == 0x21 and cb[off + 4] == 0xa9 and cb[off + 5] == 0xed
      ) committed := true;
      off += scriptLen;
      o += 1;
    };
    if (off + 4 != n) return null; // locktime, and nothing after it
    ?committed;
  };

};
