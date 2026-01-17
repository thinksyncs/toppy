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
