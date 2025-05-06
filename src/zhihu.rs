pub const VERSION: &str = "101_3_3.0";

// TODO: 如果 client 中已经带有 d_c0 的 cookie, 则不会返回新的 set-cookie, 此时尝试从 cookiejar 取
pub async fn user_device_id(client: &reqwest::Client) -> Result<String, reqwest::Error> {
    let udid = client
        .post("https://www.zhihu.com/udid")
        .send()
        .await?
        .error_for_status()?
        .headers()
        .into_iter()
        .filter(|&(name, _)| name == http::header::SET_COOKIE)
        .map(|(_, value)| value)
        .map(http::header::HeaderValue::to_str)
        .map(|value| value.expect("invalid udid SET-COOKIE encoding"))
        .map(cookie::Cookie::parse)
        .map(|value| value.expect("invalid udid SET-COOKIE format"))
        .find(|cookie| cookie.name() == "d_c0")
        .as_ref()
        .map(cookie::Cookie::value_trimmed)
        .expect("d_c0 cookie not set")
        .to_string();
    Ok(udid)
}

fn f(v: u32) -> u32 {
    const TABLE: [u8; 256] = [
        0x14, 0xdf, 0xf5, 0x07, 0xf8, 0x02, 0xc2, 0xd1, 0x57, 0x06, 0xe3, 0xfd, 0xf0, 0x80, 0xde,
        0x5b, 0xed, 0x09, 0x7d, 0x9d, 0xe6, 0x5d, 0xfc, 0xcd, 0x5a, 0x4f, 0x90, 0xc7, 0x9f, 0xc5,
        0xba, 0xa7, 0x27, 0x25, 0x9c, 0xc6, 0x26, 0x2a, 0x2b, 0xa8, 0xd9, 0x99, 0x0f, 0x67, 0x50,
        0xbd, 0x47, 0xbf, 0x61, 0x54, 0xf7, 0x5f, 0x24, 0x45, 0x0e, 0x23, 0x0c, 0xab, 0x1c, 0x72,
        0xb2, 0x94, 0x56, 0xb6, 0x20, 0x53, 0x9e, 0x6d, 0x16, 0xff, 0x5e, 0xee, 0x97, 0x55, 0x4d,
        0x7c, 0xfe, 0x12, 0x04, 0x1a, 0x7b, 0xb0, 0xe8, 0xc1, 0x83, 0xac, 0x8f, 0x8e, 0x96, 0x1e,
        0x0a, 0x92, 0xa2, 0x3e, 0xe0, 0xda, 0xc4, 0xe5, 0x01, 0xc0, 0xd5, 0x1b, 0x6e, 0x38, 0xe7,
        0xb4, 0x8a, 0x6b, 0xf2, 0xbb, 0x36, 0x78, 0x13, 0x2c, 0x75, 0xe4, 0xd7, 0xcb, 0x35, 0xef,
        0xfb, 0x7f, 0x51, 0x0b, 0x85, 0x60, 0xcc, 0x84, 0x29, 0x73, 0x49, 0x37, 0xf9, 0x93, 0x66,
        0x30, 0x7a, 0x91, 0x6a, 0x76, 0x4a, 0xbe, 0x1d, 0x10, 0xae, 0x05, 0xb1, 0x81, 0x3f, 0x71,
        0x63, 0x1f, 0xa1, 0x4c, 0xf6, 0x22, 0xd3, 0x0d, 0x3c, 0x44, 0xcf, 0xa0, 0x41, 0x6f, 0x52,
        0xa5, 0x43, 0xa9, 0xe1, 0x39, 0x70, 0xf4, 0x9b, 0x33, 0xec, 0xc8, 0xe9, 0x3a, 0x3d, 0x2f,
        0x64, 0x89, 0xb9, 0x40, 0x11, 0x46, 0xea, 0xa3, 0xdb, 0x6c, 0xaa, 0xa6, 0x3b, 0x95, 0x34,
        0x69, 0x18, 0xd4, 0x4e, 0xad, 0x2d, 0x00, 0x74, 0xe2, 0x77, 0x88, 0xce, 0x87, 0xaf, 0xc3,
        0x19, 0x5c, 0x79, 0xd0, 0x7e, 0x8b, 0x03, 0x4b, 0x8d, 0x15, 0x82, 0x62, 0xf1, 0x28, 0x9a,
        0x42, 0xb8, 0x31, 0xb5, 0x2e, 0xf3, 0x58, 0x65, 0xb7, 0x08, 0x17, 0x48, 0xbc, 0x68, 0xb3,
        0xd2, 0x86, 0xfa, 0xc9, 0xa4, 0x59, 0xd8, 0xca, 0xdc, 0x32, 0xdd, 0x98, 0x8c, 0x21, 0xeb,
        0xd6,
    ];
    let vs = v.to_be_bytes();
    let w = u32::from_be_bytes(std::array::from_fn(|k| TABLE[vs[k] as usize]));
    w ^ w.rotate_left(2) ^ w.rotate_left(10) ^ w.rotate_left(18) ^ w.rotate_left(24)
}

fn r(vs: &mut [u8]) {
    assert_eq!(vs.len(), 16);
    const TABLE: [u32; 32] = [
        0b_0100_0101_1100_0110_0010_1001_0011_0010,
        0b_0011_1101_0001_0101_1111_0010_1111_1110,
        0b_0101_0100_0100_0010_1110_0001_0100_1111,
        0b_1110_1011_1000_1001_0010_0001_1100_0000,
        0b_1101_0010_0101_0110_0101_0100_0010_1110,
        0b_1010_1110_0010_1000_1100_1011_1101_1110,
        0b_1111_0111_0111_1000_0010_1011_0000_1000,
        0b_1110_1110_0100_1000_1010_1000_1000_0011,
        0b_0111_0011_0011_1110_1000_1101_0001_1010,
        0b_1100_0110_0001_1100_1101_1111_1111_1011,
        0b_1110_0111_1100_0110_0000_0001_0110_1010,
        0b_0001_1011_0111_0001_0011_1000_0111_0110,
        0b_1101_1111_0101_1110_1110_1011_0000_1010,
        0b_1000_1111_0100_0100_1010_0110_1100_1010,
        0b_1001_1011_1110_1011_0000_0111_1010_0011,
        0b_0111_1110_0101_0110_0100_1110_1001_0100,
        0b_1000_0111_0000_1011_1100_1011_1100_1011,
        0b_0111_1001_0100_1101_0000_0010_0110_1100,
        0b_1010_0101_0100_1111_0111_0010_0011_1010,
        0b_1111_1111_1010_1010_1011_1111_0001_1001,
        0b_1111_1011_0101_1101_1001_1100_1100_0011,
        0b_1000_0011_0010_1010_1000_0011_0110_0011,
        0b_1011_0101_1110_1000_1000_0100_1111_1010,
        0b_0101_1110_0010_1011_0110_0000_1100_1111,
        0b_0100_1110_1100_1001_0011_1011_0101_0010,
        0b_0001_1011_0011_1010_0111_0111_0001_0100,
        0b_1010_1101_0000_1101_0011_0011_0000_1111,
        0b_1111_0010_0101_0101_0001_1111_1101_1111,
        0b_0001_0011_1010_1011_0111_0001_1001_0110,
        0b_1101_0000_1111_1001_0110_1010_1101_1110,
        0b_0001_0101_1010_1011_1001_1111_0111_1101,
        0b_1000_1011_1110_0101_1101_1000_0111_1011,
    ];
    let mut ws = [0; 4];
    ws[0] = u32::from_be_bytes(std::array::from_fn(|k| vs[k]));
    ws[1] = u32::from_be_bytes(std::array::from_fn(|k| vs[k + 4]));
    ws[2] = u32::from_be_bytes(std::array::from_fn(|k| vs[k + 8]));
    ws[3] = u32::from_be_bytes(std::array::from_fn(|k| vs[k + 12]));
    for k in 0..32 {
        ws[k % 4] ^= f(ws[(k + 1) & 4] ^ ws[(k + 2) % 4] ^ ws[(k + 3) % 4] ^ TABLE[k]);
    }
    vs[12..16].copy_from_slice(&ws[0].to_be_bytes());
    vs[8..12].copy_from_slice(&ws[1].to_be_bytes());
    vs[4..8].copy_from_slice(&ws[2].to_be_bytes());
    vs[0..4].copy_from_slice(&ws[3].to_be_bytes());
}

/// 字节流整体异或
/// lhs 逐字节异或 rhs 对应位置字节
fn xor_slice_in_place(lhs: &mut [u8], rhs: &[u8]) {
    assert_eq!(lhs.len(), rhs.len());
    lhs.iter_mut().zip(rhs).for_each(|(lhs, rhs)| *lhs ^= rhs);
}

pub fn encode(user_device_id: &str, url: &url::Url) -> [u8; 68] {
    use base64::Engine;
    use digest::Digest;
    let url = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let plain = [VERSION, url, user_device_id].join("+");
    let md5_sum = format!("{:x}", md5::Md5::digest(&plain));
    let mut vs = [0u8; 48];
    vs[0] = rand::random();
    vs[2..34].copy_from_slice(md5_sum.as_bytes());
    vs[34..48].fill(14);

    // 开始自定义加密
    const IV: &[u8] = &[
        26, 31, 19, 26, 31, 25, 76, 29, 78, 27, 31, 79, 26, 27, 78, 29,
    ];
    // 为了解决所有权问题所以写得比较丑陋，本质上就是
    // v0, v1, v2 = vs[00..16], vs[16..32], vs[32..48]
    let (v0, ws) = vs.split_at_mut(16);
    let (v1, v2) = ws.split_at_mut(16);
    xor_slice_in_place(v0, IV); // v0 ^= IV
    r(v0);
    xor_slice_in_place(v1, v0); // v1 ^= v0
    r(v1);
    xor_slice_in_place(v2, v1); // v2 ^= v1
    r(v2);
    vs[3..].iter_mut().step_by(4).for_each(|v| *v ^= 58);

    // 将加密字节流进行（自定义字符集的）Base64
    // 需要注意它的结果字符集除了顺序打乱之外，还包含了 '=' 字符，而缺了 'E' 字符
    // 但是 Rust 的 base64 不允许字符集中存在 PAD_BYTE 即 '='，所以这里将 '#' 放到 '=' 的位置
    // 最后再 replace('#', '=') 回来
    const ALPHABET: Result<base64::alphabet::Alphabet, base64::alphabet::ParseAlphabetError> =
        base64::alphabet::Alphabet::new(
            "6fpLRqJO8M/c3jnYxFkUVC4ZIG12SiH#5v0mXDazWBTsuw7QetbKdoPyAl+hN9rg",
        );
    const CONFIG: base64::engine::GeneralPurposeConfig =
        // 不会有 padding，因为输入永远是 48 字符是 3 的倍数，不过不妨加一道保险
        base64::engine::GeneralPurposeConfig::new().with_encode_padding(false);
    static ENCODER: std::sync::LazyLock<base64::engine::GeneralPurpose> =
        std::sync::LazyLock::new(|| {
            base64::engine::GeneralPurpose::new(&ALPHABET.unwrap(), CONFIG)
        });
    // 最终的结果是 "2.0_" + weird_base64_encode(v).reverse()
    let mut buffer = [0u8; 68];
    buffer[..4].copy_from_slice(b"2.0_");
    ENCODER
        .encode_slice(vs, &mut buffer[4..])
        .expect("base64 encode");
    buffer[4..].reverse();
    // 这里是替换 '#' 回 '='
    buffer[4..]
        .iter_mut()
        .filter(|&&mut byte| byte == b'#')
        .for_each(|byte| *byte = b'=');
    buffer
}

mod test {
    #[tokio::test]
    async fn simple_request() {
        let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
        let domain: url::Url = url::Url::parse("https://www.zhihu.com/").expect("domain url parse");
        jar.add_cookie_str(include_str!("secret/zhihu.txt"), &domain); // 如果被 40352 频控则需要设置，账号登录信息 Cookie 中找 "z_c0=......"

        let client = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/136.0.0.0 Safari/537.36", // 不设置会导致直接被拦截
            )
            .default_headers(http::HeaderMap::from_iter(
                [
                    ("x-zse-93", super::VERSION),
                    // 试了几下不是必需的，但还是加上吧
                    (http::header::REFERER.as_str(), "https://www.zhihu.com/"),
                ]
                .map(|(name, value)| (http::HeaderName::from_static(name), value))
                .map(|(name, value)| (name, http::HeaderValue::from_static(value))),
            ))
            .build()
            .expect("client build");
        let udid = super::user_device_id(&client).await.expect("udid");

        #[derive(serde::Deserialize)]
        struct Error {
            #[serde(default)]
            code: i32,
            message: String,
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Response<M> {
            Success { data: M },
            Failure { error: Error },
        }

        async fn test_req(client: &reqwest::Client, udid: &str, url: &str) {
            let url = url::Url::parse(url).expect("url parsing");
            let zse96 = super::encode(udid, &url);
            let res = client
                .get(url)
                .header("x-zse-96", &zse96[..])
                .send()
                .await
                .expect("network reading header")
                .json::<Response<serde_json::Value>>()
                .await
                .expect("deserializing body");
            match res {
                Response::Success { data } => {
                    println!("{}", serde_json::to_string_pretty(&data).unwrap())
                }
                Response::Failure { error } => panic!("{}: {}", error.code, error.message),
            }
        }

        let url = "https://www.zhihu.com/api/v3/feed/topstory/recommend?action=down&ad_interval=-10&after_id=5&desktop=true&end_offset=5&page_number=2";
        test_req(&client, &udid, url).await;

        // 无他，知乎 CEO
        let url = "https://www.zhihu.com/api/v3/moments/zhouyuan/activities?limit=5&desktop=true&ws_qiangzhisafe=0";
        test_req(&client, &udid, url).await;
    }
}
