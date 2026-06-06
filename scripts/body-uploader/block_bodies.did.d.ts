import type { Principal } from '@icp-sdk/core/principal';
import type { ActorMethod } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';

export interface BatchPutResult {
  'last_error' : [] | [string],
  'duplicate' : bigint,
  'accepted' : bigint,
}
export interface Body { 'tx_count' : bigint, 'first_txdbidx' : bigint }
export interface PutOk {
  'duplicate' : boolean,
  'tx_count' : bigint,
  'dbidx' : bigint,
  'first_txdbidx' : bigint,
}
export interface Request {
  'url' : string,
  'method' : string,
  'body' : Uint8Array | number[],
  'headers' : Array<[string, string]>,
}
export interface Response {
  'body' : Uint8Array | number[],
  'headers' : Array<[string, string]>,
  'status_code' : number,
}
export type Result = { 'ok' : PutOk } |
  { 'err' : string };
export type Result_1 = { 'ok' : BatchPutResult } |
  { 'err' : string };
export interface StableTrieStats {
  'byte_size' : bigint,
  'node_count' : bigint,
  'leaf_count' : bigint,
}
export interface Stats {
  'body_capacity_blocks' : bigint,
  'indexed_txids' : bigint,
}
export interface TxLocation { 'position' : bigint, 'dbidx' : bigint }
export interface _SERVICE {
  'body_region_byte_size' : ActorMethod<[], bigint>,
  'cycles_balance' : ActorMethod<[], bigint>,
  'get_body' : ActorMethod<[bigint], [] | [Body]>,
  'http_request' : ActorMethod<[Request], Response>,
  'lookup_txdbidx' : ActorMethod<[Uint8Array | number[]], [] | [bigint]>,
  'lookup_txid' : ActorMethod<[Uint8Array | number[]], [] | [TxLocation]>,
  'put_bodies' : ActorMethod<
    [Array<[Uint8Array | number[], bigint, Uint8Array | number[]]>],
    Result_1
  >,
  'put_body' : ActorMethod<
    [Uint8Array | number[], bigint, Uint8Array | number[]],
    Result
  >,
  'stats' : ActorMethod<[], Stats>,
  'tx_at' : ActorMethod<[bigint, bigint], [] | [Uint8Array | number[]]>,
  'tx_count_of' : ActorMethod<[bigint], [] | [bigint]>,
  'txid_of_txdbidx' : ActorMethod<[bigint], [] | [Uint8Array | number[]]>,
  'txid_trie_memory_stats' : ActorMethod<[], StableTrieStats>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
