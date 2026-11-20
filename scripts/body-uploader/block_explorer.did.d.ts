import type { Principal } from '@icp-sdk/core/principal';
import type { ActorMethod } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';

export interface BodyBatchResult {
  'last_error' : [] | [string],
  'duplicate' : bigint,
  'accepted' : bigint,
}
export type BodyBatchResultR = { 'ok' : BodyBatchResult } |
  { 'err' : string };
export interface BodyChunkOk {
  'height' : bigint,
  'offset' : bigint,
  'complete' : boolean,
  'first_tx_index' : bigint,
}
export type BodyChunkResult = { 'ok' : BodyChunkOk } |
  { 'err' : string };
export type ChunkStart = { 'offset' : bigint } |
  { 'coinbase_tx' : Uint8Array | number[] };
export interface PushBodyOk {
  'height' : bigint,
  'canonical_indexed' : boolean,
  'duplicate' : boolean,
  'tx_count' : bigint,
  'first_tx_index' : bigint,
}
export type PushBodyResult = { 'ok' : PushBodyOk } |
  { 'err' : string };
export interface TxidTip { 'height' : bigint, 'offset' : bigint }
export interface _SERVICE {
  'bodies_next_height' : ActorMethod<[], bigint>,
  'have_hashes' : ActorMethod<[Array<string>], Array<boolean>>,
  'push_bodies' : ActorMethod<
    [
      Array<
        [
          Uint8Array | number[],
          Array<Uint8Array | number[]>,
          Uint8Array | number[],
        ]
      >,
    ],
    BodyBatchResultR
  >,
  'push_body' : ActorMethod<
    [
      Uint8Array | number[],
      Array<Uint8Array | number[]>,
      Uint8Array | number[],
    ],
    PushBodyResult
  >,
  'push_body_chunk' : ActorMethod<
    [
      Uint8Array | number[],
      ChunkStart,
      Array<Uint8Array | number[]>,
      Array<Uint8Array | number[]>,
    ],
    BodyChunkResult
  >,
  'txid_tip' : ActorMethod<[], TxidTip>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
