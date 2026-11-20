export const idlFactory = ({ IDL }) => {
  const BodyBatchResult = IDL.Record({
    'last_error' : IDL.Opt(IDL.Text),
    'duplicate' : IDL.Nat,
    'accepted' : IDL.Nat,
  });
  const BodyBatchResultR = IDL.Variant({
    'ok' : BodyBatchResult,
    'err' : IDL.Text,
  });
  const PushBodyOk = IDL.Record({
    'height' : IDL.Nat,
    'canonical_indexed' : IDL.Bool,
    'duplicate' : IDL.Bool,
    'tx_count' : IDL.Nat,
    'first_tx_index' : IDL.Nat,
  });
  const PushBodyResult = IDL.Variant({ 'ok' : PushBodyOk, 'err' : IDL.Text });
  const ChunkStart = IDL.Variant({
    'offset' : IDL.Nat,
    'coinbase_tx' : IDL.Vec(IDL.Nat8),
  });
  const BodyChunkOk = IDL.Record({
    'height' : IDL.Nat,
    'offset' : IDL.Nat,
    'complete' : IDL.Bool,
    'first_tx_index' : IDL.Nat,
  });
  const BodyChunkResult = IDL.Variant({ 'ok' : BodyChunkOk, 'err' : IDL.Text });
  const TxidTip = IDL.Record({ 'height' : IDL.Nat, 'offset' : IDL.Nat });
  return IDL.Service({
    'bodies_next_height' : IDL.Func([], [IDL.Nat], ['query']),
    'have_hashes' : IDL.Func(
        [IDL.Vec(IDL.Text)],
        [IDL.Vec(IDL.Bool)],
        ['query'],
      ),
    'push_bodies' : IDL.Func(
        [
          IDL.Vec(
            IDL.Tuple(
              IDL.Vec(IDL.Nat8),
              IDL.Vec(IDL.Vec(IDL.Nat8)),
              IDL.Vec(IDL.Nat8),
            )
          ),
        ],
        [BodyBatchResultR],
        [],
      ),
    'push_body' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Vec(IDL.Nat8)), IDL.Vec(IDL.Nat8)],
        [PushBodyResult],
        [],
      ),
    'push_body_chunk' : IDL.Func(
        [
          IDL.Vec(IDL.Nat8),
          ChunkStart,
          IDL.Vec(IDL.Vec(IDL.Nat8)),
          IDL.Vec(IDL.Vec(IDL.Nat8)),
        ],
        [BodyChunkResult],
        [],
      ),
    'txid_tip' : IDL.Func([], [TxidTip], ['query']),
  });
};
export const init = ({ IDL }) => { return []; };
