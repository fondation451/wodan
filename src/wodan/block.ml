[@@@warning "-32"]
[@@@warning "-34"]

module type EXTBLOCK = sig
  include Mirage_types_lwt.BLOCK

  val discard : t -> int64 -> int64 -> (unit, write_error) result io
end

module type SUPERBLOCK_PARAMS = sig
  (* Size of blocks, in bytes *)
  val block_size : int

  (* The exact size of all keys, in bytes *)
  val key_size : int
end

module type S = sig
  type t

  type node =
    [ `Root
    | `Child ]

  val mk : int -> node -> int64 -> string -> int32 -> int32 option -> (string * string) Seq.t -> int -> int -> t

(*   val set_node : t -> node -> int64 -> int32 -> (string * string) Seq.t -> int -> int -> unit
 *)end

module Make (B : EXTBLOCK) (P : SUPERBLOCK_PARAMS) : S with type t = B.page_aligned_buffer list = struct
  type t = Cstruct.t list

  [%%cstruct
  type superblock = {
    magic : uint8_t; [@len 16]
    (* major version, all later fields may change if this does *)
    version : uint32_t;
    compat_flags : uint32_t;
    (* refuse to mount if unknown incompat_flags are set *)
    incompat_flags : uint32_t;
    block_size : uint32_t;
    key_size : uint8_t;
    first_block_written : uint64_t;
    logical_size : uint64_t;
    (* FSID is UUID-sized (128 bits) *)
    fsid : uint8_t; [@len 16]
    reserved : uint8_t; [@len 443]
    crc : uint32_t
  }
  [@@little_endian]]

  [%%cstruct
  type anynode_hdr = {
    nodetype : uint8_t;
    generation : uint64_t;
    fsid : uint8_t; [@len 16]
    value_count : uint32_t
  }
  [@@little_endian]]

  [%%cstruct
  type rootnode_hdr = {
    (* nodetype = 1 *)
    nodetype : uint8_t;
    (* will this wrap? there's no uint128_t. Nah, flash will wear out first. *)
    generation : uint64_t;
    fsid : uint8_t; [@len 16]
    value_count : uint32_t;
    depth : uint32_t
  }
  [@@little_endian]]

  [%%cstruct
  type childnode_hdr = {
    (* nodetype = 2 *)
    nodetype : uint8_t;
    generation : uint64_t;
    fsid : uint8_t; [@len 16]
    value_count : uint32_t
  }
  [@@little_endian]]

  let superblock_magic = "MIRAGE KVFS \xf0\x9f\x90\xaa"
  let sizeof_datalen = 2

  let () = assert (String.length superblock_magic = 16)
  let () = assert (sizeof_superblock = 512)
  let () = assert (sizeof_anynode_hdr = 29)
  let () = assert (sizeof_rootnode_hdr = 33)
  let () = assert (sizeof_childnode_hdr = 29)

  type node =
    [ `Root
    | `Child ]

  let header_size = function
    | `Root ->
      sizeof_rootnode_hdr
    | `Child ->
      sizeof_childnode_hdr
  
  let node_ty_id node_ty =
    match node_ty with
    | `Root -> 1
    | `Child -> 2
  
  let make_fanned_io_list size cstr =
    let r = ref [] in
    let l = Cstruct.len cstr in
    let rec iter off =
      if off <= 0 then
        ()
      else
        let off = off - size in
        r := Cstruct.sub cstr off size :: !r;
        iter off
    in
    iter l; !r
  
  let _get_block_io () =
    if P.block_size >= Io_page.page_size then
      Io_page.get_buf ~n:(P.block_size / Io_page.page_size) ()
    else
      (* This will only work on Unix, which has buffered IO instead of direct IO.
            Allows more efficient fuzzing. *)
      Cstruct.create P.block_size
  
  let resize data size =
    match data with
      | [] -> assert false
      | d::_ ->
        if Cstruct.len d < size then
          Cstruct.set_len d size
        else
          d
    
  let set_node_ty d node_ty = set_anynode_hdr_nodetype d (node_ty_id node_ty)

  let set_hdr data node_ty gen fsid val_count depth =
    set_node_ty data node_ty;
    set_anynode_hdr_generation data gen;
    blit_anynode_hdr_fsid (Cstruct.of_string fsid) 0 data;
    set_anynode_hdr_value_count data val_count;
    match node_ty, depth with
    | `Root, Some d -> set_rootnode_hdr_depth data d
    | `Root, None -> assert false
    | _ -> ()
  
  let set_data data off seq value_end =
    let offset =
      Seq.fold_left
        (fun off (k, v) ->
          let len = String.length v in
          let len1 = len + P.key_size + sizeof_datalen in
          Cstruct.blit_from_string k 0 data off P.key_size;
          Cstruct.LE.set_uint16 data (off + P.key_size) len;
          Cstruct.blit_from_string v 0 data (off + P.key_size + sizeof_datalen) len;
          off + len1)
        off
        seq
    in
    assert (offset = value_end)
  
  (*
      Erase the end of the data which is not used.
      Put 0 instead
  *)
  let set_padding data value_end old_value_end =
    if value_end < old_value_end then
      let len = old_value_end - value_end in
      Cstruct.blit (Cstruct.create len) 0 data value_end len
  
  let set_node data node_ty gen fsid val_count depth seq value_end old_value_end =
    set_hdr data node_ty gen fsid val_count depth;
    set_data data (header_size node_ty) seq value_end;
    set_padding data value_end old_value_end;
    Wodan_crc32c.cstruct_reset data
  
  let mk size node_ty gen fsid val_count depth seq value_end old_value_end =
    make_fanned_io_list size
    (set_node (_get_block_io ()) node_ty gen fsid val_count depth seq value_end old_value_end)
end