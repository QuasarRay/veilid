use crate::resolver::non_windows::config::{default_name_servers, parse_resolv_conf, DNS_PORT};
use crate::resolver::non_windows::dns::message::*;
use crate::resolver::non_windows::dns::{
    classify, ptr_record, query, query_with, txt_records, DnsError, ResolutionStrategy,
};
use crate::resolver::reverse_name;
use crate::*;

const TEST_TIMEOUT_MS: u32 = 300;

//////////////////////////////////////////////////////////////////////////////////
// Wire format fixtures

fn encoded(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_name(name, &mut out).expect("should encode");
    out
}

pub fn test_encode_name() {
    info!("test_encode_name");
    assert_eq!(encoded("example.com"), b"\x07example\x03com\x00");
    // A trailing dot is the same absolute name
    assert_eq!(encoded("example.com."), encoded("example.com"));

    for bad in [
        "a..b",
        ".example",
        "",
        ".",
        "b\u{fc}cher.example",
        &format!("{}.example", "a".repeat(64)),
        &format!("{}.example", vec!["a".repeat(60); 5].join(".")),
    ] {
        let mut out = Vec::new();
        assert!(
            matches!(encode_name(bad, &mut out), Err(DnsError::InvalidName(_))),
            "should reject {:?}",
            bad
        );
    }
}

pub fn test_build_query() {
    info!("test_build_query");
    let q = build_query(0x1234, "example.com", TYPE_TXT, Some(EDNS_UDP_PAYLOAD))
        .expect("should build query");
    assert_eq!(
        q,
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\
          \x07example\x03com\x00\x00\x10\x00\x01\
          \x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
            .to_vec()
    );

    let plain = build_query(0x1234, "example.com", TYPE_TXT, None).expect("should build query");
    assert_eq!(plain.len(), q.len() - 11);
    assert_eq!(&plain[10..12], &[0, 0], "no additional records");
}

//////////////////////////////////////////////////////////////////////////////////
// Response builder used by the fixtures and by the fake nameserver

#[derive(Clone)]
struct Answer {
    name: String,
    rtype: u16,
    rdata: Vec<u8>,
}

impl Answer {
    fn txt(name: &str, strings: &[&[u8]]) -> Self {
        let mut rdata = Vec::new();
        for s in strings {
            rdata.push(s.len() as u8);
            rdata.extend_from_slice(s);
        }
        Self {
            name: name.to_string(),
            rtype: TYPE_TXT,
            rdata,
        }
    }

    fn ptr(name: &str, target: &str) -> Self {
        let mut rdata = Vec::new();
        encode_name(target, &mut rdata).expect("should encode");
        Self {
            name: name.to_string(),
            rtype: TYPE_PTR,
            rdata,
        }
    }
}

struct ResponseBuilder {
    id: u16,
    flags: u16,
    question: (String, u16),
    answers: Vec<Answer>,
    additional: Vec<Answer>,
}

impl ResponseBuilder {
    fn new(id: u16, name: &str, qtype: u16) -> Self {
        Self {
            id,
            // QR + RD + RA
            flags: 0x8180,
            question: (name.to_string(), qtype),
            answers: Vec::new(),
            additional: Vec::new(),
        }
    }

    fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    fn rcode(mut self, rcode: u16) -> Self {
        self.flags = (self.flags & !0x000F) | rcode;
        self
    }

    fn answer(mut self, answer: Answer) -> Self {
        self.answers.push(answer);
        self
    }

    fn opt(mut self, ttl: u32) -> Self {
        self.additional.push(Answer {
            name: String::new(),
            rtype: TYPE_OPT,
            rdata: ttl.to_be_bytes().to_vec(),
        });
        self
    }

    fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(self.additional.len() as u16).to_be_bytes());
        encode_name(&self.question.0, &mut out).expect("should encode");
        out.extend_from_slice(&self.question.1.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        for rr in self.answers.iter().chain(self.additional.iter()) {
            if rr.rtype == TYPE_OPT {
                // OPT carries its extended rcode and version in the TTL field
                out.push(0);
                out.extend_from_slice(&TYPE_OPT.to_be_bytes());
                out.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
                out.extend_from_slice(&rr.rdata);
                out.extend_from_slice(&0u16.to_be_bytes());
                continue;
            }
            if rr.name == self.question.0 {
                // Compression pointer back to the question's name
                out.extend_from_slice(&[0xC0, HEADER_LEN as u8]);
            } else {
                encode_name(&rr.name, &mut out).expect("should encode");
            }
            out.extend_from_slice(&rr.rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            out.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rr.rdata);
        }
        out
    }
}

pub fn test_parse_txt() {
    info!("test_parse_txt");
    let msg = ResponseBuilder::new(0x1111, "example.com", TYPE_TXT)
        .answer(Answer::txt("example.com", &[b"ab", b"cd"]))
        .answer(Answer::txt("other.example.com", &[b"chased"]))
        .answer(Answer::txt("example.com", &[&[0xff, 0xfe]]))
        .build();
    let resp = parse_response(&msg).expect("should parse");
    assert!(resp.matches(0x1111, "example.com", TYPE_TXT));
    // Multi-string records join, chased owners count, non-UTF-8 records drop
    assert_eq!(txt_records(&resp), vec!["abcd", "chased"]);
}

pub fn test_parse_ptr() {
    info!("test_parse_ptr");
    let msg = ResponseBuilder::new(0x2222, "4.3.2.1.in-addr.arpa", TYPE_PTR)
        .answer(Answer::ptr("4.3.2.1.in-addr.arpa", "host.example"))
        .build();
    let resp = parse_response(&msg).expect("should parse");
    assert_eq!(ptr_record(&resp).as_deref(), Some("host.example"));
}

pub fn test_response_matching() {
    info!("test_response_matching");
    let msg = ResponseBuilder::new(0x3333, "example.com", TYPE_TXT)
        .answer(Answer::txt("example.com", &[b"x"]))
        .build();
    let resp = parse_response(&msg).expect("should parse");
    assert!(resp.matches(0x3333, "EXAMPLE.COM", TYPE_TXT));
    assert!(resp.matches(0x3333, "example.com.", TYPE_TXT));
    assert!(!resp.matches(0x3334, "example.com", TYPE_TXT));
    assert!(!resp.matches(0x3333, "other.com", TYPE_TXT));
    assert!(!resp.matches(0x3333, "example.com", TYPE_PTR));

    // A query echoed back without the QR bit is not an answer
    let query = build_query(0x3333, "example.com", TYPE_TXT, None).expect("should build");
    let echoed = parse_response(&query).expect("should parse");
    assert!(!echoed.matches(0x3333, "example.com", TYPE_TXT));
}

pub fn test_classify() {
    info!("test_classify");
    let answered = ResponseBuilder::new(1, "example.com", TYPE_TXT)
        .answer(Answer::txt("example.com", &[b"x"]))
        .build();
    let parse = |msg: &[u8]| parse_response(msg).expect("should parse");
    assert!(classify(parse(&answered)).is_ok());

    let truncated = ResponseBuilder::new(1, "example.com", TYPE_TXT)
        .flags(0x8380)
        .answer(Answer::txt("example.com", &[b"x"]))
        .build();
    assert!(matches!(
        classify(parse(&truncated)),
        Err(DnsError::Truncated)
    ));

    let nxdomain = ResponseBuilder::new(1, "example.com", TYPE_TXT)
        .rcode(RCODE_NXDOMAIN)
        .build();
    assert!(matches!(
        classify(parse(&nxdomain)),
        Err(DnsError::NoRecords { rcode: 3 })
    ));

    let nodata = ResponseBuilder::new(1, "example.com", TYPE_TXT).build();
    assert!(matches!(
        classify(parse(&nodata)),
        Err(DnsError::NoRecords { rcode: 0 })
    ));

    let servfail = ResponseBuilder::new(1, "example.com", TYPE_TXT)
        .rcode(2)
        .build();
    assert!(matches!(
        classify(parse(&servfail)),
        Err(DnsError::Rcode(2))
    ));

    // BADVERS lives in the OPT record's extended rcode bits
    let badvers = ResponseBuilder::new(1, "example.com", TYPE_TXT)
        .rcode(0)
        .opt(0x0100_0000)
        .build();
    assert!(matches!(
        classify(parse(&badvers)),
        Err(DnsError::Rcode(16))
    ));
}

pub fn test_parse_malformed() {
    info!("test_parse_malformed");
    let good = ResponseBuilder::new(0x4444, "example.com", TYPE_TXT)
        .answer(Answer::txt("example.com", &[b"x"]))
        .build();

    assert!(
        parse_response(&good[..HEADER_LEN - 1]).is_err(),
        "short header"
    );
    assert!(
        parse_response(&good[..good.len() - 1]).is_err(),
        "truncated rdata"
    );

    // A pointer at the question's name that points at or past itself
    let mut forward = good.clone();
    forward[HEADER_LEN] = 0xC0;
    forward[HEADER_LEN + 1] = (HEADER_LEN + 4) as u8;
    assert!(parse_response(&forward).is_err(), "forward pointer");

    let mut selfref = good.clone();
    selfref[HEADER_LEN] = 0xC0;
    selfref[HEADER_LEN + 1] = HEADER_LEN as u8;
    assert!(parse_response(&selfref).is_err(), "self pointer");

    let mut bad_kind = good.clone();
    bad_kind[HEADER_LEN] = 0x40;
    assert!(parse_response(&bad_kind).is_err(), "reserved label type");

    // RDLENGTH claiming more bytes than the message holds
    let mut long_rdata = good.clone();
    let rdlen_pos = long_rdata.len() - 3 - 1;
    long_rdata[rdlen_pos] = 0xFF;
    assert!(parse_response(&long_rdata).is_err(), "rdlength overrun");

    // A TXT character-string longer than its rdata
    let mut long_txt = good.clone();
    let last = long_txt.len() - 2;
    long_txt[last] = 0x7F;
    assert!(parse_response(&long_txt).is_err(), "txt string overrun");
}

pub fn test_reverse_name() {
    info!("test_reverse_name");
    assert_eq!(
        reverse_name(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        "4.3.2.1.in-addr.arpa"
    );
    assert_eq!(
        reverse_name(IpAddr::V6("2001:db8::1".parse().expect("should parse"))),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}

pub fn test_parse_resolv_conf() {
    info!("test_parse_resolv_conf");
    let servers = parse_resolv_conf(
        "# a comment\n\
         ; another comment\n\
         search example.com\n\
         options edns0 trust-ad\n\
         nameserver 192.168.1.2\n\
         nameserver 192.168.1.2\n\
         nameserver 2606:4700:4700::1111\n\
         nameserver fe80::1%1\n\
         nameserver fe80::2%nosuchif0\n\
         nameserver not-an-address\n\
         nameserver\n\
         junk line\n",
    );
    assert_eq!(
        servers,
        vec![
            SocketAddr::new("192.168.1.2".parse().expect("should parse"), DNS_PORT),
            SocketAddr::new(
                "2606:4700:4700::1111".parse().expect("should parse"),
                DNS_PORT
            ),
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::1".parse().expect("should parse"),
                DNS_PORT,
                0,
                1
            )),
        ]
    );
    assert!(parse_resolv_conf("").is_empty());
}

//////////////////////////////////////////////////////////////////////////////////
// Loopback nameserver

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Answer,
    AnswerAfter(u32),
    Truncate,
    Ignore,
    Rcode(u16),
    Nxdomain,
    AnswerUnlessOpt,
}

#[derive(Default)]
struct Hits {
    udp: usize,
    tcp: usize,
}

struct FakeDns {
    addr: SocketAddr,
    hits: Arc<Mutex<Hits>>,
    tasks: Vec<MustJoinHandle<()>>,
}

impl FakeDns {
    fn start(udp_mode: Mode, tcp_mode: Mode) -> Self {
        // One port serving both transports, as a real nameserver does
        let (udp_socket, tcp_listener, addr) = loop {
            let udp_socket =
                bind_async_udp_socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                    .expect("udp bind should not error")
                    .expect("udp bind should succeed");
            let addr = udp_socket.local_addr().expect("should have local addr");
            if let Some(tcp_listener) = bind_async_tcp_listener(addr).expect("tcp bind") {
                break (udp_socket, tcp_listener, addr);
            }
        };

        let hits = Arc::new(Mutex::new(Hits::default()));
        let udp_hits = hits.clone();
        let udp_task = spawn("test dns udp server", async move {
            serve_udp(udp_socket, udp_mode, udp_hits).await;
        });
        let tcp_hits = hits.clone();
        let tcp_task = spawn("test dns tcp server", async move {
            serve_tcp(tcp_listener, tcp_mode, tcp_hits).await;
        });

        Self {
            addr,
            hits,
            tasks: vec![udp_task, tcp_task],
        }
    }

    fn hits(&self) -> (usize, usize) {
        let hits = self.hits.lock();
        (hits.udp, hits.tcp)
    }

    async fn stop(self) {
        for task in self.tasks {
            task.abort().await;
        }
    }
}

/// The reply a mode produces for a query, or `None` to stay silent
async fn reply_for(query: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let parsed = parse_response(query).expect("server should parse the query");
    let question = parsed
        .questions
        .first()
        .expect("query should have a question");
    let carries_opt = query.len() > HEADER_LEN + 4 + question.name.len() + 2 + 4;
    let builder = ResponseBuilder::new(parsed.id, &question.name, question.qtype);
    let answered = match question.qtype {
        TYPE_PTR => builder.answer(Answer::ptr(&question.name, "fake.example")),
        _ => builder.answer(Answer::txt(&question.name, &[b"fake", b"-record"])),
    };
    match mode {
        Mode::Answer => Some(answered.build()),
        Mode::AnswerAfter(ms) => {
            sleep(ms).await;
            Some(answered.build())
        }
        Mode::Truncate => Some(
            ResponseBuilder::new(parsed.id, &question.name, question.qtype)
                .flags(0x8380)
                .build(),
        ),
        Mode::Ignore => None,
        Mode::Rcode(rcode) => Some(
            ResponseBuilder::new(parsed.id, &question.name, question.qtype)
                .rcode(rcode)
                .build(),
        ),
        Mode::Nxdomain => Some(
            ResponseBuilder::new(parsed.id, &question.name, question.qtype)
                .rcode(RCODE_NXDOMAIN)
                .build(),
        ),
        Mode::AnswerUnlessOpt => {
            if carries_opt {
                Some(
                    ResponseBuilder::new(parsed.id, &question.name, question.qtype)
                        .rcode(1)
                        .build(),
                )
            } else {
                Some(answered.build())
            }
        }
    }
}

async fn serve_udp(socket: UdpSocket, mode: Mode, hits: Arc<Mutex<Hits>>) {
    let mut buf = vec![0u8; MAX_UDP_MESSAGE_LEN];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        hits.lock().udp += 1;
        if let Some(reply) = reply_for(&buf[..n], mode).await {
            if socket.send_to(&reply, from).await.is_err() {
                return;
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, mode: Mode, hits: Arc<Mutex<Hits>>) {
    use futures_util::{AsyncReadExt, AsyncWriteExt};
    // A silent server holds its connections open; closing them would be an error, not silence
    let mut held = Vec::new();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        hits.lock().tcp += 1;
        #[cfg(feature = "rt-tokio")]
        let mut stream = stream.compat();
        #[cfg(feature = "rt-async-std")]
        let mut stream = stream;

        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            continue;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        if stream.read_exact(&mut query).await.is_err() {
            continue;
        }
        match reply_for(&query, mode).await {
            Some(reply) => {
                let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                let _ = stream.write_all(&framed).await;
                let _ = stream.flush().await;
            }
            None => held.push(stream),
        }
    }
}

async fn lookup(
    servers: &[SocketAddr],
    qtype: u16,
    strategy: ResolutionStrategy,
) -> Result<Response, DnsError> {
    query_with(servers, "fake.example", qtype, strategy, TEST_TIMEOUT_MS).await
}

async fn test_both_transports_answer() {
    info!("test_both_transports_answer");
    let fake = FakeDns::start(Mode::Answer, Mode::Answer);
    let resp = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect("should resolve");
    assert_eq!(txt_records(&resp), vec!["fake-record"]);
    fake.stop().await;
}

async fn test_tcp_answers_when_udp_is_dead() {
    info!("test_tcp_answers_when_udp_is_dead");
    let fake = FakeDns::start(Mode::Ignore, Mode::Answer);
    let resp = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect("should resolve over tcp");
    assert_eq!(txt_records(&resp), vec!["fake-record"]);
    assert_eq!(fake.hits().1, 1);
    fake.stop().await;
}

async fn test_udp_answers_when_tcp_is_dead() {
    info!("test_udp_answers_when_tcp_is_dead");
    let fake = FakeDns::start(Mode::Answer, Mode::Ignore);
    let resp = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect("should resolve over udp");
    assert_eq!(txt_records(&resp), vec!["fake-record"]);
    fake.stop().await;
}

async fn test_truncated_udp_yields_to_tcp() {
    info!("test_truncated_udp_yields_to_tcp");
    let fake = FakeDns::start(Mode::Truncate, Mode::Answer);
    let resp = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect("should resolve over tcp");
    assert_eq!(txt_records(&resp), vec!["fake-record"]);
    fake.stop().await;

    // The serial strategy has to notice the TC bit and retry the same server over TCP
    let fake = FakeDns::start(Mode::Truncate, Mode::Answer);
    let resp = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Serial)
        .await
        .expect("should resolve over tcp");
    assert_eq!(txt_records(&resp), vec!["fake-record"]);
    assert_eq!(fake.hits(), (1, 1));
    fake.stop().await;
}

async fn test_silent_server_times_out() {
    info!("test_silent_server_times_out");
    let fake = FakeDns::start(Mode::Ignore, Mode::Ignore);
    let start = get_raw_timestamp();
    let err = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect_err("should time out");
    assert!(matches!(err, DnsError::Timeout), "got {}", err);
    let elapsed_ms = (get_raw_timestamp() - start) / 1000;
    assert!(
        elapsed_ms >= u64::from(TEST_TIMEOUT_MS),
        "returned too early"
    );
    fake.stop().await;
}

async fn test_failing_server_yields_to_a_working_one() {
    info!("test_failing_server_yields_to_a_working_one");
    let broken = FakeDns::start(Mode::Rcode(2), Mode::Rcode(2));
    let working = FakeDns::start(Mode::Answer, Mode::Answer);
    for strategy in [ResolutionStrategy::Simultaneous, ResolutionStrategy::Serial] {
        let resp = lookup(&[broken.addr, working.addr], TYPE_TXT, strategy)
            .await
            .expect("should resolve from the working server");
        assert_eq!(txt_records(&resp), vec!["fake-record"]);
    }
    broken.stop().await;
    working.stop().await;
}

async fn test_nxdomain_ends_the_lookup() {
    info!("test_nxdomain_ends_the_lookup");
    let denying = FakeDns::start(Mode::Nxdomain, Mode::Nxdomain);
    let slow = FakeDns::start(Mode::AnswerAfter(200), Mode::AnswerAfter(200));
    let start = get_raw_timestamp();
    let err = lookup(
        &[denying.addr, slow.addr],
        TYPE_TXT,
        ResolutionStrategy::Simultaneous,
    )
    .await
    .expect_err("nxdomain is definitive");
    assert!(
        matches!(err, DnsError::NoRecords { rcode: 3 }),
        "got {}",
        err
    );
    let elapsed_ms = (get_raw_timestamp() - start) / 1000;
    assert!(elapsed_ms < 200, "should not wait for the slow answer");
    denying.stop().await;
    slow.stop().await;
}

async fn test_edns_hostile_server_answers_over_tcp() {
    info!("test_edns_hostile_server_answers_over_tcp");
    let fake = FakeDns::start(Mode::AnswerUnlessOpt, Mode::AnswerUnlessOpt);
    let resp = lookup(&[fake.addr], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect("tcp query carries no opt");
    assert_eq!(txt_records(&resp), vec!["fake-record"]);
    fake.stop().await;
}

async fn test_ptr_over_loopback() {
    info!("test_ptr_over_loopback");
    let fake = FakeDns::start(Mode::Answer, Mode::Answer);
    let resp = lookup(&[fake.addr], TYPE_PTR, ResolutionStrategy::Simultaneous)
        .await
        .expect("should resolve");
    assert_eq!(ptr_record(&resp).as_deref(), Some("fake.example"));
    fake.stop().await;
}

async fn test_no_nameservers() {
    info!("test_no_nameservers");
    let err = lookup(&[], TYPE_TXT, ResolutionStrategy::Simultaneous)
        .await
        .expect_err("empty list");
    assert!(matches!(err, DnsError::NoNameServers), "got {}", err);
}

//////////////////////////////////////////////////////////////////////////////////

/// The Apple backend must agree with the resolv.conf configd writes on macOS
#[cfg(target_os = "macos")]
pub fn test_apple_system_name_servers() {
    use crate::resolver::non_windows::apple_resolv;
    info!("test_apple_system_name_servers");
    let from_libresolv =
        apple_resolv::system_name_servers().expect("libresolv should list servers");
    let from_file = parse_resolv_conf(
        &std::fs::read_to_string("/etc/resolv.conf").expect("should read resolv.conf"),
    );
    let addrs =
        |servers: Vec<SocketAddr>| -> HashSet<IpAddr> { servers.iter().map(|s| s.ip()).collect() };
    assert_eq!(addrs(from_libresolv), addrs(from_file));
}

/// Runs only on a device, from `run_all_tests`: the platform system resolver and a real lookup
#[allow(dead_code)]
pub async fn test_platform_system_resolver() {
    info!("test_platform_system_resolver");

    #[cfg(target_os = "ios")]
    {
        use crate::resolver::non_windows::apple_resolv;
        let servers = apple_resolv::system_name_servers();
        info!("ios libresolv nameservers: {:?}", servers);
        assert!(servers.is_some(), "libresolv should list nameservers");
    }

    #[cfg(target_os = "android")]
    {
        use crate::resolver::non_windows::android_resolv;
        // android_res_nquery arrives in API 29; below that the fallback list carries the lookup
        let available = android_resolv::available();
        info!("android_res_nquery available: {}", available);
        if available {
            let resp = android_resolv::query("bootstrap-v1.veilid.net", TYPE_TXT)
                .await
                .expect("os resolver should answer");
            let records = txt_records(&resp);
            info!("android os resolver TXT: {:?}", records);
            assert!(!records.is_empty(), "should return records");
        }
    }

    let records = Resolver::txt_lookup("bootstrap-v1.veilid.net")
        .await
        .expect("should resolve bootstrap txt");
    info!("device txt_lookup: {:?}", records);
    assert!(!records.is_empty(), "should return records");
}

pub async fn test_all() {
    #[cfg(target_os = "macos")]
    test_apple_system_name_servers();
    test_encode_name();
    test_build_query();
    test_parse_txt();
    test_parse_ptr();
    test_response_matching();
    test_classify();
    test_parse_malformed();
    test_reverse_name();
    test_parse_resolv_conf();

    test_both_transports_answer().await;
    test_tcp_answers_when_udp_is_dead().await;
    test_udp_answers_when_tcp_is_dead().await;
    test_truncated_udp_yields_to_tcp().await;
    test_silent_server_times_out().await;
    test_failing_server_yields_to_a_working_one().await;
    test_nxdomain_ends_the_lookup().await;
    test_edns_hostile_server_answers_over_tcp().await;
    test_ptr_over_loopback().await;
    test_no_nameservers().await;
}

/// Resolves against the real network; excluded from the offline unit test gate
#[allow(dead_code)]
pub async fn test_live() {
    info!("test_live");
    let txt = Resolver::txt_lookup("bootstrap-v1.veilid.net")
        .await
        .expect("should resolve bootstrap txt");
    assert!(!txt.is_empty(), "should return records");
    assert!(
        txt.iter().all(|r| !r.is_empty()),
        "records should have text"
    );

    let name = Resolver::ptr_lookup(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        .await
        .expect("should reverse-resolve");
    assert!(!name.is_empty(), "should return a hostname");

    // The fallback list on its own, which the race would otherwise hide behind the system resolver
    let resp = query(&default_name_servers(), "bootstrap-v1.veilid.net", TYPE_TXT)
        .await
        .expect("fallback nameservers should answer");
    assert!(!txt_records(&resp).is_empty(), "should return records");
}
