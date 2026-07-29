#[cfg(test)]
pub mod test {
    use rstest::{rstest, fixture};
    use url::Url;
    use crate::{main_decrypt, main_encrypt, main_reduce, main_verify};
    use magic_cap::{ImmutableReadCap, ImmutableWebCatalog};
    use magic_cap::err::MagicCapError;
    use proptest::prelude::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::str::FromStr;
    use tempfile::tempdir;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::{Builder, Runtime};

    async fn process(socket: TcpStream) {
        println!("process {:?}", socket);
    }

    async fn _run_web(listener: TcpListener) {
        println!("listener {:?}", listener);
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            println!("new socket {:?}", socket);
            // A new task is spawned for each inbound socket. The socket is
            // moved to the new task and processed there.
            tokio::spawn(async move {
                process(socket).await;
            });
        }
    }

    #[derive(Debug)]
    struct CatalogServer {
        server: JoinHandle<()>,
        runtime: Runtime,
    }

    #[fixture]
    fn catalog_server() -> CatalogServer {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("catalog-server-runtime")
            .enable_all()
            .build()
            .unwrap();


        println!("spawn web");
        let _guard = runtime.enter();

        use warp::Filter;

        let js = warp::path!("magic-cap-catalog")
            .map(|| "{\"version\": 0}");

        let handle = tokio::spawn(
            warp::serve(warp::fs::dir("../data/published/"))
                .run(([127, 0, 0, 1], 4321))
        );

        println!("//spawn web");
        CatalogServer { server: handle, runtime }
    }

    use tokio::task::JoinHandle;

    #[rstest]
    fn web_fetch(catalog_server: CatalogServer ) {
        // fetech a thing using Catalog
        // - start a warp web server
        // - run it as a fixture (rstest)
        // - make a reqwest req
        // - replace above with Catalog

        println!("web_fetch test {:?}", catalog_server);

        let root = Url::parse("http://127.0.0.1:4321/").expect("valid url");
        println!("{:?}", root);
        // todo: should "create()" be like "open()" or something?
        let catalog = ImmutableWebCatalog::create(root).expect("catalog");
        println!("catalog {:?}", catalog);

        // we have a valid catalog, which made on reqwest to a warp server!
        use magic_cap::{ImmutableIdentifier, ImmutableReadCap};
        let rcap: ImmutableReadCap = "mcap0rEVJOakvltxontWVh2K9Qehglbk9MNt-C8nzyyo0c1_vYpTy8fbIlzCOlFHs3HK0g".try_into().unwrap();
        let id: ImmutableIdentifier = rcap.into();
        let res = catalog.fetch_metadata(&id);
        println!("FOO {:?}", res);
        res.unwrap();
    }

    #[test]
    fn reduce_unknown() {
        let capstr = "mcap0x_deadbeef";
        let mut output = vec![];
        if let Err(x) = main_reduce(&mut output, capstr) {
            match x {
                MagicCapError::InvalidCap(_) => (),
                _ => {
                    panic!("Unexpected error")
                }
            }
        } else {
            panic!("Expected an error");
        }
    }

    proptest! {
        #[test]
        fn mcap_round_trip_main(s in "\\PC+") {
            // write to a file so we can exercise via paths
            println!("we have reached the inside of mcap round_trip_main proptest");
            let outd = tempdir()?;
            let plain = outd.path().join("plain");
            println!("creating plain file at {:?}",plain);
            {
                let mut tmp = File::create(&plain)?;
                let _written_amount = tmp.write(s.as_bytes())?;
            }  // close tmp
            println!("finished writing to tmp");
            let cipher = outd.path().join("cipher");
            let mut output = vec!();
            main_encrypt(&mut output, &plain, &Some(cipher.clone()), &None, 4096).unwrap();

            let capstr: &str = std::str::from_utf8(&output)?.trim_end();
            let round = outd.path().join("decrypted");

            // turn this into a Verify Cap and confirm the ciphertext
            let mut output = vec!();
            main_reduce(&mut output, capstr)?;
            let verifycap = std::str::from_utf8(&output)?.trim_end();
            main_verify(verifycap, &cipher).unwrap();

            // "reducing" a Verify Cap is a no-op
            let mut output = vec!();
            main_reduce(&mut output, verifycap).unwrap();
            assert_eq!(String::from_utf8(output).unwrap().trim(), verifycap);

            // confirm that "decrypt" can turn back into plaintext
            let immutable_read_cap = ImmutableReadCap::from_str(capstr).unwrap();
            // XXX why does this test pass? The println at the top certainly runs! Something is wrong here!
            main_decrypt(&immutable_read_cap, &vec![], &vec![], &vec![cipher], &vec![], &Some(round.clone())).unwrap();

            let mut og = String::new();
            let mut other = String::new();
            println!("opening plain to og");
            File::open(plain)?.read_to_string(&mut og)?;
            println!("opening round to other");
            File::open(round)?.read_to_string(&mut other)?;

            assert_eq!(og, other);
        }
    }
}
