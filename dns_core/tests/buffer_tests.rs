use dns_core::buffer::BytePacketBuffer;

#[test]
fn respects_buffer_boundaries_and_positions() {
    let mut buffer = BytePacketBuffer::new();

    for i in 0..512u16 {
        // All writes within the buffer should succeed
        buffer.write_u8((i & 0xFF) as u8).unwrap();
    }

    // The 513th byte should error because the buffer is full
    assert!(buffer.write_u8(0).is_err());

    buffer.seek(0);
    assert_eq!(0, buffer.pos());
    assert_eq!(0, buffer.read().unwrap());

    buffer.step(10);
    assert_eq!(11, buffer.pos());
    assert_eq!(10, buffer.get(10).unwrap());
}
