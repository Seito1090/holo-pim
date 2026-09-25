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
pub fn compute(data: &[u8]) -> u16 {
    let mut accumulator: u32 = 0;
    let mut reste = data;

    // Inner loop
    while reste.len() > 1{
        let value: u16 = u16::from_be_bytes([reste[0], reste[1]]);
        accumulator += value as u32;
        reste = &reste[2..];
    }

    // Left over byte if any
    if !reste.is_empty(){
        let value: u16 = u16::from_be_bytes([reste[0], 0x00]);
        accumulator += value as u32;
    }

    // Fold 32 bit sum to 16 bits
    while (accumulator >> 16) != 0 {
        accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

#[cfg(test)]
mod tests{ 
    use super::*;

    #[test]
    fn rfc_example(){
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = compute(&data);
        let correct= !0xddf2;
        assert_eq!(correct, checksum);
    }

    #[test]
    fn pimlike_example(){
        let data = [0x00, 0x01, 0x00, 0x00, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = compute(&data);
        let correct= 0x1411;
        assert_eq!(correct, checksum);
    }

    #[test]
    fn compute_on_checksum(){
        let data = [0x00, 0x01, 0x14, 0x11, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = compute(&data);
        let correct= !0xFFFF;
        assert_eq!(correct, checksum); 
    }
}
