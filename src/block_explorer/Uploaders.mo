// Uploader registry: maps uploader principal <-> id and tracks, per id, the
// push-ordered list of block hashes that principal first contributed.
//
// Bundled in an `Uploaders` record for dot-notation (`uploaders.record(h, p)`
// == `Uploaders.record(uploaders, h, p)`). The anonymous principal is
// registered like any other but its individual blocks are not stored (only
// counted) — `of` returns the anonymous principal for any unattributed hash.
//
// `ofHash` is a reverse index (hash -> id) for non-anonymous blocks. Unlike
// the old class design it is NOT rebuilt on upgrade: as a top-level stable
// structure it persists directly.

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Map "mo:core/Map";
import Principal "mo:core/Principal";
import Runtime "mo:core/Runtime";

import Enum "mo:enumeration";

module {

  type BlobEnum = Enum.BlobEnumeration.BlobEnumeration;

  public type Uploaders = {
    enum : BlobEnum; // principal-blob <-> id
    blocks : List.List<List.List<Blob>>; // id -> push-ordered block hashes
    ofHash : Map.Map<Blob, Nat>; // hash -> id (non-anonymous only)
    var anonymousCount : Nat;
  };

  public func empty() : Uploaders = {
    enum = Enum.BlobEnumeration.empty();
    blocks = List.empty<List.List<Blob>>();
    ofHash = Map.empty<Blob, Nat>();
    var anonymousCount = 0;
  };

  func anonymousPrincipal() : Principal = Principal.fromText("2vxsx-fae");

  // Register `p` and return its id, growing `blocks` to match.
  func findOrAdd(self : Uploaders, p : Principal) : Nat {
    let id = Enum.BlobEnumeration.add(self.enum, p.toBlob());
    while (self.blocks.size() <= id) {
      self.blocks.add(List.empty<Blob>());
    };
    id;
  };

  // Record that block `hash` was first pushed by `uploader`. Called once, at
  // the block's first insertion (canonical or fork).
  public func record(self : Uploaders, hash : Blob, uploader : Principal) {
    let id = findOrAdd(self, uploader);
    if (uploader.isAnonymous()) {
      self.anonymousCount += 1;
    } else {
      switch (self.blocks.get(id)) {
        case (?lst) lst.add(hash);
        case null Runtime.trap("Uploaders.record: missing block list for id " # debug_show id);
      };
      self.ofHash.add(Blob.compare, hash, id);
    };
  };

  // Resolve the uploader principal for a block hash; unattributed -> anonymous.
  public func of(self : Uploaders, hash : Blob) : Principal {
    switch (self.ofHash.get(Blob.compare, hash)) {
      case (?id) Principal.fromBlob(Enum.BlobEnumeration.at(self.enum, id));
      case null anonymousPrincipal();
    };
  };

  // Number of distinct uploaders registered.
  public func count(self : Uploaders) : Nat = Enum.BlobEnumeration.size(self.enum);

  // (uploader, headers-pushed) per distinct uploader, in registration order.
  public func stats(self : Uploaders) : [(Principal, Nat)] {
    let n = Enum.BlobEnumeration.size(self.enum);
    Array.tabulate<(Principal, Nat)>(
      n,
      func(i) {
        let p = Principal.fromBlob(Enum.BlobEnumeration.at(self.enum, i));
        let c = if (p.isAnonymous()) {
          self.anonymousCount;
        } else {
          switch (self.blocks.get(i)) {
            case (?lst) lst.size();
            case null 0;
          };
        };
        (p, c);
      },
    );
  };

  // Page through the block hashes uploaded by `p`, newest first. Anonymous
  // returns []: its blocks are not tracked individually.
  public func blocksByUploader(self : Uploaders, p : Principal, offset : Nat, limit : Nat) : [Blob] {
    if (p.isAnonymous() or limit == 0) return [];
    let id = switch (Enum.BlobEnumeration.lookup(self.enum, p.toBlob())) {
      case (?i) i;
      case null return [];
    };
    let lst = switch (self.blocks.get(id)) {
      case (?l) l;
      case null return [];
    };
    let n = lst.size();
    if (offset >= n) return [];
    let remaining : Nat = n - offset;
    let take = if (limit < remaining) limit else remaining;
    Array.tabulate<Blob>(
      take,
      func(k) {
        let pos : Nat = n - 1 - offset - k;
        switch (lst.get(pos)) {
          case (?h) h;
          case null Runtime.trap("Uploaders.blocksByUploader: index out of range");
        };
      },
    );
  };

};
