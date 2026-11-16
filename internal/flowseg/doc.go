// Package flowseg is Woodshed's flow segment format, `.wsf` (SPEC §13.2):
// one columnar file per device per received hour, at
// logs/<device>/flows/<YYYY-MM-DD>T<HH>.wsf (parts …T09.001.wsf).
//
// # Layout (format version 1, little-endian, CRC-32C on every section)
//
// Header: 32 fixed bytes, then the device ID and the writer's version:
//
//	0  8  magic "WSFLOW01"
//	8  2  format version (1)
//	10 2  header length H = 32 + D + V
//	12 4  the received hour, in hours since the Unix epoch (UTC)
//	16 2  D, the device ID's length (at most 1,024)
//	18 2  V, the writer version's length (at most 256)
//	20 8  created, unix ms
//	28 4  CRC-32C of bytes [0, 28) followed by [32, H)
//	32 D  device ID, then V bytes of version
//
// A device ID is often longer than a fixed 32-byte header could hold (IPv6
// device IDs), so the header has a length field and the ID follows the fixed
// part.
//
// Sections follow, each framed as magic (4 bytes), body length (u32) and the
// body's CRC-32C (u32), then the body:
//
//   - "WSB1" a block of records (below);
//   - "WSR1" a chunk of raw sets: data that never got its template, and
//     malformed packets (SPEC §13.1.3), each with its received time, exporter
//     port, domain, version, the set ID it needed, its status, its export
//     header and its bytes;
//   - "WSC1" a template chunk: the template definitions (and the exporter
//     metadata, when it changed) first used since the previous chunk, written
//     before the block that uses them, so a crashed segment still decodes and
//     exports on its own;
//   - at close, "WST1" the whole template table and metadata, then "WSF1" the
//     footer, then a 16-byte trailer: the footer body's length (u32), its
//     CRC-32C (u32) and "WSFLOWEN".
//
// The raw section and the template table of SPEC §13.2 are thus written as
// chunks between blocks as data arrives (an hour of raw sets isn't held in
// memory), and the footer lists the raw chunks.
//
// # Blocks
//
// A block holds up to 65,536 records or 1 s of arrivals. Its body is the
// header length (uvarint), the header, the column directory and the columns.
// The header: row count; min and max received; min and max effective flow
// start and end (EffectiveTimes); the stored-column mask; the block's totals
// (records, bytes and packets under the no-double-count rule, scaled bytes and
// packets, records with unknown sampling, records by status); the distinct
// sampling rates and domains; the index; and the block's per-minute counts
// (Minute), so a footer can be rebuilt from blocks alone. The index is a
// 256-bit protocol bitmap, the distinct input and output interfaces (a list up
// to 64, else a Bloom filter) and a Bloom filter (about 1 % false positives)
// over the source, destination and post-NAT addresses, their /24 or /48
// prefixes, and the source, destination and post-NAT ports. The post-NAT
// fields are in the filter so the post_nat_* and ip_any filters skip blocks
// too.
//
// The directory lists each stored column: ID (its Cols bit position; 62 is
// the block's address dictionary), flags (1: DEFLATE), raw and stored
// lengths. Every column is encoded for its type and then DEFLATE-compressed
// (level 1), or stored as is when compression doesn't shrink it:
//
//   - optional columns (the flow.Has* bits) start with a presence bitmap as
//     run lengths (absent, present, absent, …), then a value per present row:
//     times as zigzag varints of the difference from the column's block
//     minimum (stored first); addresses as varint indexes into the block's
//     dictionary of 16-byte addresses (IPv4-mapped); integers as varints;
//     protocol, ToS, direction, end reason and the event codes as bytes;
//     rule_id and the interface names as a per-block string dictionary and
//     varint indexes; HasTotals as presence alone;
//   - received times as zigzag varints from the block minimum;
//   - sampling, exporter_domain (version, exporter port, domain), template
//     (table index + 1, template ID), status and time source as runs (length,
//     values), and left out when every row is zero;
//   - extras: a presence bitmap, then per record a count and (enterprise
//     number, element ID, value) entries.
//
// A column no record of the block has isn't written at all.
//
// # Footer
//
// The footer holds the device ID, hour and writer version, the segment's
// totals, raw set counts, received and flow-time ranges, sampling rates and
// domains, the per-minute table (the sum of the blocks' minutes), the
// template table's offset, every block's offset, length and a copy of its
// header (the index repeated), and the raw chunk directory.
//
// # Crash safety
//
// A segment being written has no footer. Recover reads its sections in
// order, keeps every one whose CRC checks up to the first that doesn't (or is
// cut short), cuts the file there and writes the table and footer. Readers of
// a live segment use the writer's Snapshot, which lists only complete
// sections.
package flowseg
