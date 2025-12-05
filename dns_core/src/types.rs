#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, PartialOrd, Ord)]
pub enum QueryType {
    UNKNOWN(u16),
    A,         // 1
    NS,        // 2
    CNAME,     // 5
    SOA,       // 6
    PTR,       // 12
    HINFO,     // 13
    MINFO,     // 14
    MX,        // 15
    TXT,       // 16
    RP,        // 17
    AFSDB,     // 18
    X25,       // 19
    ISDN,      // 20
    RT,        // 21
    NSAP,      // 22
    NSAP_PTR,  // 23
    SIG,       // 24
    KEY,       // 25
    PX,        // 26
    AAAA,      // 28
    LOC,       // 29
    SRV,       // 33
    NAPTR,     // 35
    KX,        // 36
    CERT,      // 37
    DNAME,     // 39
    OPT,       // 41
    APL,       // 42
    DS,        // 43
    SSHFP,     // 44
    IPSECKEY,  // 45
    RRSIG,     // 46
    NSEC,      // 47
    DNSKEY,    // 48
    DHCID,     // 49
    NSEC3,     // 50
    NSEC3PARAM,// 51
    TLSA,      // 52
    SMIMEA,    // 53
    HIP,       // 55
    CDS,       // 59
    CDNSKEY,   // 60
    OPENPGPKEY,// 61
    CSYNC,     // 62
    ZONEMD,    // 63
    SVCB,      // 64
    HTTPS,     // 65
    SPF,       // 99
    NID,       // 104
    L32,       // 105
    L64,       // 106
    LP,        // 107
    EUI48,     // 108
    EUI64,     // 109
    TKEY,      // 249
    TSIG,      // 250
    IXFR,      // 251
    AXFR,      // 252
    ANY,       // 255
    URI,       // 256
    CAA,       // 257
    AVC,       // 258
    DOA,       // 259
    AMTRELAY,  // 260
    TA,        // 32768
    DLV,       // 32769
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::PTR => 12,
            QueryType::HINFO => 13,
            QueryType::MINFO => 14,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::RP => 17,
            QueryType::AFSDB => 18,
            QueryType::X25 => 19,
            QueryType::ISDN => 20,
            QueryType::RT => 21,
            QueryType::NSAP => 22,
            QueryType::NSAP_PTR => 23,
            QueryType::SIG => 24,
            QueryType::KEY => 25,
            QueryType::PX => 26,
            QueryType::AAAA => 28,
            QueryType::LOC => 29,
            QueryType::SRV => 33,
            QueryType::NAPTR => 35,
            QueryType::KX => 36,
            QueryType::CERT => 37,
            QueryType::DNAME => 39,
            QueryType::OPT => 41,
            QueryType::APL => 42,
            QueryType::DS => 43,
            QueryType::SSHFP => 44,
            QueryType::IPSECKEY => 45,
            QueryType::RRSIG => 46,
            QueryType::NSEC => 47,
            QueryType::DNSKEY => 48,
            QueryType::DHCID => 49,
            QueryType::NSEC3 => 50,
            QueryType::NSEC3PARAM => 51,
            QueryType::TLSA => 52,
            QueryType::SMIMEA => 53,
            QueryType::HIP => 55,
            QueryType::CDS => 59,
            QueryType::CDNSKEY => 60,
            QueryType::OPENPGPKEY => 61,
            QueryType::CSYNC => 62,
            QueryType::ZONEMD => 63,
            QueryType::SVCB => 64,
            QueryType::HTTPS => 65,
            QueryType::SPF => 99,
            QueryType::NID => 104,
            QueryType::L32 => 105,
            QueryType::L64 => 106,
            QueryType::LP => 107,
            QueryType::EUI48 => 108,
            QueryType::EUI64 => 109,
            QueryType::TKEY => 249,
            QueryType::TSIG => 250,
            QueryType::IXFR => 251,
            QueryType::AXFR => 252,
            QueryType::ANY => 255,
            QueryType::URI => 256,
            QueryType::CAA => 257,
            QueryType::AVC => 258,
            QueryType::DOA => 259,
            QueryType::AMTRELAY => 260,
            QueryType::TA => 32768,
            QueryType::DLV => 32769,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            12 => QueryType::PTR,
            13 => QueryType::HINFO,
            14 => QueryType::MINFO,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            17 => QueryType::RP,
            18 => QueryType::AFSDB,
            19 => QueryType::X25,
            20 => QueryType::ISDN,
            21 => QueryType::RT,
            22 => QueryType::NSAP,
            23 => QueryType::NSAP_PTR,
            24 => QueryType::SIG,
            25 => QueryType::KEY,
            26 => QueryType::PX,
            28 => QueryType::AAAA,
            29 => QueryType::LOC,
            33 => QueryType::SRV,
            35 => QueryType::NAPTR,
            36 => QueryType::KX,
            37 => QueryType::CERT,
            39 => QueryType::DNAME,
            41 => QueryType::OPT,
            42 => QueryType::APL,
            43 => QueryType::DS,
            44 => QueryType::SSHFP,
            45 => QueryType::IPSECKEY,
            46 => QueryType::RRSIG,
            47 => QueryType::NSEC,
            48 => QueryType::DNSKEY,
            49 => QueryType::DHCID,
            50 => QueryType::NSEC3,
            51 => QueryType::NSEC3PARAM,
            52 => QueryType::TLSA,
            53 => QueryType::SMIMEA,
            55 => QueryType::HIP,
            59 => QueryType::CDS,
            60 => QueryType::CDNSKEY,
            61 => QueryType::OPENPGPKEY,
            62 => QueryType::CSYNC,
            63 => QueryType::ZONEMD,
            64 => QueryType::SVCB,
            65 => QueryType::HTTPS,
            99 => QueryType::SPF,
            104 => QueryType::NID,
            105 => QueryType::L32,
            106 => QueryType::L64,
            107 => QueryType::LP,
            108 => QueryType::EUI48,
            109 => QueryType::EUI64,
            249 => QueryType::TKEY,
            250 => QueryType::TSIG,
            251 => QueryType::IXFR,
            252 => QueryType::AXFR,
            255 => QueryType::ANY,
            256 => QueryType::URI,
            257 => QueryType::CAA,
            258 => QueryType::AVC,
            259 => QueryType::DOA,
            260 => QueryType::AMTRELAY,
            32768 => QueryType::TA,
            32769 => QueryType::DLV,
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
