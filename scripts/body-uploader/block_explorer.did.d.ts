import type { ActorMethod } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';

export interface PushBodyOk {
  'height' : bigint,
  'tx_count' : bigint,
  'first_tx_index' : bigint,
  'canonical_indexed' : boolean,
  'duplicate' : boolean,
}
export type PushBodyResult = { 'ok' : PushBodyOk } | { 'err' : string };
export interface BodyBatchResult {
  'accepted' : bigint,
  'duplicate' : bigint,
  'last_error' : [] | [string],
}
export type BodyBatchResultR = { 'ok' : BodyBatchResult } | { 'err' : string };
export interface _SERVICE {
  'bodies_next_height' : ActorMethod<[], bigint>,
  'push_bodies' : ActorMethod<
    [Array<[Uint8Array | number[], bigint, Uint8Array | number[]]>],
    BodyBatchResultR
  >,
  'push_body' : ActorMethod<
    [Uint8Array | number[], bigint, Uint8Array | number[]],
    PushBodyResult
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
