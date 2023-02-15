//! Utreexo implementation for rust-bitcoin
use std::io::ErrorKind;

use crate::consensus::{self, Decodable, Encodable};
use crate::hash_types::BlockHash;
use crate::internal_macros::impl_consensus_encoding;
use crate::{Block, VarInt};
/// commitment of the LeafData.
///
/// The serialized format is:
/// [<block hash><outpoint><header code><amount><pkscript len><pkscript>]
///
/// The outpoint serialized format is:
/// [<tx hash><index>]
///
/// The serialized header code format is:
///   bit 0 - containing transaction is a coinbase
///   bits 1-x - height of the block that contains the spent txout
///
/// It's calculated with:
///   header_code = <<= 1
///   if IsCoinBase {
///       header_code |= 1 // only set the bit 0 if it's a coinbase.
///   }
///
/// All together, the serialization looks like so:
///
/// Field              Type       Size
/// block hash         [32]byte   32
/// outpoint           -          36
///   tx hash          [32]byte   32
///   vout             [4]byte    4
/// header code        int32      4
/// amount             int64      8
/// pkscript length    VLQ        variable
/// pkscript           []byte     variable
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CompactLeafData {
    height: u32,
    amount: u64,
    spk_ty: u8,
}
/// BatchProof serialization defines how the utreexo accumulator proof will be
/// serialized both for i/o.
///
/// Note that this serialization format differs from the one from
/// github.com/mit-dci/utreexo/accumulator as this serialization method uses
/// varints and the one in that package does not.  They are not compatible and
/// should not be used together.  The serialization method here is more compact
/// and thus is better for wire and disk storage.
///
/// The serialized format is:
/// [<target count><targets><proof count><proofs>]
///
/// All together, the serialization looks like so:
/// Field          Type       Size
/// target count   varint     1-8 bytes
/// targets        []uint64   variable
/// hash count     varint     1-8 bytes
/// hashes         []32 byte  variable
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct BatchProof {
    /// All targets that'll be deleted
    pub targets: Vec<VarInt>,
    /// The inner hashes of a proof
    pub hashes: Vec<BlockHash>,
}
/// UData contains data needed to prove the existence and validity of all inputs
/// for a Bitcoin block.  With this data, a full node may only keep the utreexo
/// roots and still be able to fully validate a block.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct UData {
    /// All the indexes of new utxos to remember.
    remember_idx: Vec<u64>,
    /// AccProof is the utreexo accumulator proof for all the inputs.
    proof: BatchProof,
    // LeafData are the tx validation data for every input.
    leafs: Vec<CompactLeafData>,
}

/// A block plus some udata
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoBlock {
    /// A actual block
    block: Block,
    /// The utreexo specific data
    udata: Option<UData>,
}

impl Encodable for UtreexoBlock {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.block.consensus_encode(writer)?;
        if let Some(ref udata) = self.udata {
            len += udata.consensus_encode(writer)?;
        }

        Ok(len)
    }
}
impl Decodable for UtreexoBlock {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::consensus::encode::Error> {
        let block = Block::consensus_decode(reader)?;
        let udata = UData::consensus_decode(reader);
        let udata = match udata {
            Ok(udata) => Some(udata),
            Err(e) => {
                if let consensus::encode::Error::Io(e) = e {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        None
                    } else {
                        return Err(consensus::encode::Error::Io(e));
                    }
                } else {
                    return Err(e);
                }
            }
        };
        Ok(Self { block, udata })
    }
}

impl_consensus_encoding!(CompactLeafData, height, amount, spk_ty);
impl_consensus_encoding!(BatchProof, targets, hashes);
impl_consensus_encoding!(UData, remember_idx, proof, leafs);

impl Into<Block> for UtreexoBlock {
    fn into(self) -> Block {
        self.block
    }
}
impl Into<UtreexoBlock> for Block {
    fn into(self) -> UtreexoBlock {
        UtreexoBlock { block: self, udata: None }
    }
}
