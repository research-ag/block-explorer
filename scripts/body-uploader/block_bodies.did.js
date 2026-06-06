export const idlFactory = ({ IDL }) => {
  const Body = IDL.Record({ 'tx_count' : IDL.Nat, 'first_txdbidx' : IDL.Nat });
  const Request = IDL.Record({
    'url' : IDL.Text,
    'method' : IDL.Text,
    'body' : IDL.Vec(IDL.Nat8),
    'headers' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Text)),
  });
  const Response = IDL.Record({
    'body' : IDL.Vec(IDL.Nat8),
    'headers' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Text)),
    'status_code' : IDL.Nat16,
  });
  const TxLocation = IDL.Record({ 'position' : IDL.Nat, 'dbidx' : IDL.Nat });
  const BatchPutResult = IDL.Record({
    'last_error' : IDL.Opt(IDL.Text),
    'duplicate' : IDL.Nat,
    'accepted' : IDL.Nat,
  });
  const Result_1 = IDL.Variant({ 'ok' : BatchPutResult, 'err' : IDL.Text });
  const PutOk = IDL.Record({
    'duplicate' : IDL.Bool,
    'tx_count' : IDL.Nat,
    'dbidx' : IDL.Nat,
    'first_txdbidx' : IDL.Nat,
  });
  const Result = IDL.Variant({ 'ok' : PutOk, 'err' : IDL.Text });
  const Stats = IDL.Record({
    'body_capacity_blocks' : IDL.Nat,
    'indexed_txids' : IDL.Nat,
  });
  const StableTrieStats = IDL.Record({
    'byte_size' : IDL.Nat,
    'node_count' : IDL.Nat,
    'leaf_count' : IDL.Nat,
  });
  return IDL.Service({
    'body_region_byte_size' : IDL.Func([], [IDL.Nat], ['query']),
    'cycles_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'get_body' : IDL.Func([IDL.Nat], [IDL.Opt(Body)], ['query']),
    'http_request' : IDL.Func([Request], [Response], ['query']),
    'lookup_txdbidx' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Opt(IDL.Nat)],
        ['query'],
      ),
    'lookup_txid' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Opt(TxLocation)],
        ['query'],
      ),
    'put_bodies' : IDL.Func(
        [IDL.Vec(IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Nat, IDL.Vec(IDL.Nat8)))],
        [Result_1],
        [],
      ),
    'put_body' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Nat, IDL.Vec(IDL.Nat8)],
        [Result],
        [],
      ),
    'stats' : IDL.Func([], [Stats], ['query']),
    'tx_at' : IDL.Func(
        [IDL.Nat, IDL.Nat],
        [IDL.Opt(IDL.Vec(IDL.Nat8))],
        ['query'],
      ),
    'tx_count_of' : IDL.Func([IDL.Nat], [IDL.Opt(IDL.Nat)], ['query']),
    'txid_of_txdbidx' : IDL.Func(
        [IDL.Nat],
        [IDL.Opt(IDL.Vec(IDL.Nat8))],
        ['query'],
      ),
    'txid_trie_memory_stats' : IDL.Func([], [StableTrieStats], ['query']),
  });
};
export const init = ({ IDL }) => { return []; };
