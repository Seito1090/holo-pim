/*
    This implements the ip checksum computation based on rfc 1071

    (1)  Adjacent octets to be checksummed are paired to form 16-bit
        integers, and the 1's complement sum of these 16-bit integers is
        formed.

   (2)  To generate a checksum, the checksum field itself is cleared,
        the 16-bit 1's complement sum is computed over the octets
        concerned, and the 1's complement of this sum is placed in the
        checksum field.

   (3)  To check a checksum, the 1's complement sum is computed over the
        same set of octets, including the checksum field.  If the result
        is all 1 bits (-0 in 1's complement arithmetic), the check
        succeeds.

    {
        /* Compute Internet Checksum for "count" bytes
        *         beginning at location "addr".
        */
       register long sum = 0;

        while( count > 1 )  {
           /*  This is the inner loop */
               sum += * (unsigned short) addr++;
               count -= 2;
       }

           /*  Add left-over byte, if any */
       if( count > 0 )
               sum += * (unsigned char *) addr;

           /*  Fold 32-bit sum to 16 bits */
       while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);

       checksum = ~sum;
   }
*/
use std::net::Ipv6Addr;

pub fn compute(data: &[u8]) -> u16 {
    let mut accumulator: u32 = 0;
    let mut reste = data;

    // Inner loop
    while reste.len() > 1 {
        let value: u16 = u16::from_be_bytes([reste[0], reste[1]]);
        accumulator += value as u32;
        reste = &reste[2..];
    }

    // Left over byte if any
    if !reste.is_empty() {
        let value: u16 = u16::from_be_bytes([reste[0], 0x00]);
        accumulator += value as u32;
    }

    // Fold 32 bit sum to 16 bits
    while (accumulator >> 16) != 0 {
        accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

/*
This function extends the checksum computation to include the pseudo-header for IPv6 packets as per RFC 8200 section 8.1.
*/
pub fn compute_ipv6(
    data: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    upper_layer_len: usize,
) -> u16 {
    // Create the pseudo-header for the IPv6 packet
    let mut pseudo_header = Vec::with_capacity(40 + data.len());

    pseudo_header.extend_from_slice(&src.octets()); // Source Address
    pseudo_header.extend_from_slice(&dst.octets()); // Destination Address
    pseudo_header.extend_from_slice(&(upper_layer_len as u32).to_be_bytes()); // Upper-Layer Packet Length
    pseudo_header.extend_from_slice(&[0, 0, 0, 103]); // Next Header field for PIM is 103
    pseudo_header.extend_from_slice(&data[..upper_layer_len]); // Upper-Layer Packet Data
    
    compute(&pseudo_header)
}
