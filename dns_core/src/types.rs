#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, PartialOrd, Ord)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{QueryType, ResultCode};

    #[test]
    fn query_type_conversions() {
        assert_eq!(QueryType::A.to_num(), 1);
        assert_eq!(QueryType::from_num(15), QueryType::MX);
        assert_eq!(QueryType::from_num(65000), QueryType::UNKNOWN(65000));
    }

    #[test]
    fn result_code_from_num_maps_all_values() {
        assert_eq!(ResultCode::from_num(0), ResultCode::NOERROR);
        assert_eq!(ResultCode::from_num(1), ResultCode::FORMERR);
        assert_eq!(ResultCode::from_num(2), ResultCode::SERVFAIL);
        assert_eq!(ResultCode::from_num(3), ResultCode::NXDOMAIN);
        assert_eq!(ResultCode::from_num(4), ResultCode::NOTIMP);
        assert_eq!(ResultCode::from_num(5), ResultCode::REFUSED);
        assert_eq!(ResultCode::from_num(250), ResultCode::NOERROR);
    }
}
