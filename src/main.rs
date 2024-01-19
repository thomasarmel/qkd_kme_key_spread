use qkd_kme_key_spread::kme::Kme;

const SUPER_SECRET_STRING: &'static str = "This string is so secret";

fn main() {
    // logs will be sent to stdout
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let secret = SUPER_SECRET_STRING.as_bytes();

    let mut kme1 = Kme::new(1);
    // KME1 is the initial KME, who will receive the secret
    kme1.set_secret(secret);
    assert!(check_retrieve_secret_ok(&kme1)); // Obviously KME1 can retrieve the secret

    let mut kme2 = Kme::new(2);
    let mut kme3 = Kme::new(3);
    let mut kme4 = Kme::new(4);
    // KME1 spread the secret shares to KME2, KME3 and KME4
    // Threshold = (3 / 2) + 1 = 2, meaning that at least 2 KMEs are required to retrieve the secret
    kme1.spread_secrets(&mut [&mut kme2, &mut kme3, &mut kme4]);
    // A hacker leaked data of KME4, fortunately it's not enough to retrieve the secret
    assert_eq!(check_retrieve_secret_ok(&kme4), false);

    let mut kme5 = Kme::new(5);
    let mut kme6 = Kme::new(6);
    let mut kme7 = Kme::new(7);
    // KMEs 2, 3 and 4 spread the shares of their sub secret shares to KMEs 5, 6 and 7
    kme2.spread_secrets(&mut [&mut kme5, &mut kme6]);
    kme3.spread_secrets(&mut [&mut kme5, &mut kme6, &mut kme7]);
    kme4.spread_secrets(&mut [&mut kme6, &mut kme7]);

    // A hacker leaked data of KME6, fortunately it's not enough to retrieve the secret
    assert_eq!(check_retrieve_secret_ok(&kme6), false);

    let mut kme8 = Kme::new(8); // The final KME

    // KMEs 5, 6 and 7 send directly the shares they received to KME8, without re encrypting as there is only 1 destination
    kme5.spread_secrets(&mut [&mut kme8]);
    kme6.spread_secrets(&mut [&mut kme8]);
    // Communication between KME7 and KME8 has been cut by a hacker, so KME7 can't send its share to KME8

    // Even with 2 of 3 sub shares, KME8 can retrieve the secret
    assert!(check_retrieve_secret_ok(&kme8));
}

fn check_retrieve_secret_ok(kme: &Kme) -> bool {
    match kme.try_retrieve_secret() {
        None => false,
        Some(secret) => {
            match std::str::from_utf8(&secret) {
                Ok(s) => s == SUPER_SECRET_STRING,
                Err(_) => false
            }
        }
    }
}