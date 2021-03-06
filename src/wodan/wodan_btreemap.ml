(********************************************************************************)
(*  Copyright 2017-2019 Gabriel de Perthuis <g2p.code@gmail.com>                *)
(*                                                                              *)
(*  Permission to use, copy, modify, and/or distribute this software for any    *)
(*  purpose with or without fee is hereby granted, provided that the above      *)
(*  copyright notice and this permission notice appear in all copies.           *)
(*                                                                              *)
(*  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES    *)
(*  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF            *)
(*  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR     *)
(*  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES      *)
(*  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN       *)
(*  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR  *)
(*  IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.                 *)
(*                                                                              *)
(********************************************************************************)

open Stdcompat

(* include Btreemap *)

(* a functional map, which we wrap in imperative style *)
module FMap = Wodan_map_407.Make (String)

type 'a t = 'a FMap.t ref

exception AlreadyExists of string

let create () = ref FMap.empty

let length m = FMap.cardinal !m

let is_empty m = !m = FMap.empty

let clear m = m := FMap.empty

let find_opt k m = FMap.find_opt k !m

let mem k m = FMap.mem k !m

let add k v m = m := FMap.add k v !m

let map1 k f m = m := FMap.update k f !m

let update k v m =
  m :=
    FMap.update k
      (function
        | Some _ ->
            Some v
        | None ->
            raise Not_found)
      !m

let xadd k v m =
  m :=
    FMap.update k
      (function
        | Some _ ->
            raise @@ AlreadyExists k
        | None ->
            Some v)
      !m

let remove k m = m := FMap.remove k !m

let iter f m = FMap.iter f !m

let iter_range start end_excl f m =
  try
    FMap.to_seq_from start !m
    |> Seq.iter (fun (k, v) ->
           if String.compare k end_excl < 0 then f k v else raise Exit )
  with Exit -> ()

let iter_inclusive_range start end_incl f m =
  try
    FMap.to_seq_from start !m
    |> Seq.iter (fun (k, v) ->
           if String.compare k end_incl <= 0 then f k v else raise Exit )
  with Exit -> ()

let fold f m acc = FMap.fold f !m acc

let exists f m = FMap.exists f !m

let min_binding m = FMap.min_binding_opt !m

let max_binding m = FMap.max_binding_opt !m

let find_first_opt k m =
  FMap.find_first_opt (fun k' -> String.compare k k' <= 0) !m

let find_last_opt k m =
  FMap.find_last_opt (fun k' -> String.compare k' k < 0) !m

let split_off_after k m =
  let m1, m2 = FMap.partition (fun k' _v -> String.compare k k' >= 0) !m in
  m := m1;
  ref m2

let carve_inclusive_range start end_incl m =
  let m1, m2 =
    FMap.partition
      (fun k _v -> String.compare start k > 0 || String.compare k end_incl > 0)
      !m
  in
  m := m1;
  ref m2

let swap m1 m2 =
  let m = !m1 in
  m1 := !m2;
  m2 := m
