use dns_core::types::{QueryType, ResultCode};

#[test]
fn query_type_to_and_from_num_are_inverse_for_known_type() {
    let qtype = QueryType::MX;
    assert_eq!(qtype, QueryType::from_num(qtype.to_num()));
}

#[test]
fn unknown_query_type_preserves_value() {
    let unknown_value = 9999;
    assert_eq!(QueryType::UNKNOWN(unknown_value), QueryType::from_num(unknown_value));
    assert_eq!(unknown_value, QueryType::UNKNOWN(unknown_value).to_num());
}

#[test]
fn result_code_from_num_handles_known_values() {
    assert_eq!(ResultCode::REFUSED, ResultCode::from_num(ResultCode::REFUSED as u8));
}
