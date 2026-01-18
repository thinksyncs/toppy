use toppy_proto::masque::{HttpDatagram, CONNECT_UDP_CONTEXT_ID};
use toppy_proto::{Capsule, ControlMessage};

#[test]
fn capsule_new_sets_fields() {
    let capsule = Capsule::new(7, vec![1, 2, 3]);
    assert_eq!(capsule.kind, 7);
    assert_eq!(capsule.payload, vec![1, 2, 3]);
}

#[test]
fn control_message_terminal_detection() {
    assert!(!ControlMessage::Ping.is_terminal());
    assert!(ControlMessage::Close {
        reason: "done".to_string()
    }
    .is_terminal());
}

#[test]
fn connect_udp_http_datagram_roundtrip() {
    let dg = HttpDatagram::new(CONNECT_UDP_CONTEXT_ID, vec![9, 8, 7]);
    let bytes = dg.encode().unwrap();
    let decoded = HttpDatagram::decode(&bytes).unwrap();
    assert_eq!(decoded, dg);
}
