export const idlFactory = ({ IDL }) => {
  const PushBodyOk = IDL.Record({
    'height' : IDL.Nat,
    'tx_count' : IDL.Nat,
    'first_tx_index' : IDL.Nat,
    'canonical_indexed' : IDL.Bool,
    'duplicate' : IDL.Bool,
  });
  const PushBodyResult = IDL.Variant({ 'ok' : PushBodyOk, 'err' : IDL.Text });
  const BodyBatchResult = IDL.Record({
    'accepted' : IDL.Nat,
    'duplicate' : IDL.Nat,
    'last_error' : IDL.Opt(IDL.Text),
  });
  const BodyBatchResultR = IDL.Variant({
    'ok' : BodyBatchResult,
    'err' : IDL.Text,
  });
  return IDL.Service({
    'bodies_next_height' : IDL.Func([], [IDL.Nat], ['query']),
    'push_bodies' : IDL.Func(
        [IDL.Vec(IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Nat, IDL.Vec(IDL.Nat8)))],
        [BodyBatchResultR],
        [],
      ),
    'push_body' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Nat, IDL.Vec(IDL.Nat8)],
        [PushBodyResult],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return []; };
