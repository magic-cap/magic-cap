#[cfg(test)]
pub mod test {
    use crate::{main_decrypt, main_encrypt, main_reduce, main_verify};
    use magic_cap::err::MagicCapError;
    use magic_cap::{ImmutableReadCap, ImmutableWebCatalog};
    use proptest::prelude::*;
    use rstest::{fixture, rstest};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::str::FromStr;
    use tempfile::tempdir;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::{Builder, Runtime};
    use url::Url;

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

        // todo:
        //
        // - can we implement some trait in ImmutableWebCatalog so
        // that Warp can "just serve" things at the right spots?
        // (e.g. Shae speculates "warp::reply::Reply" or similar)
        //
        // - failing ^ can we at least do in-memory stuff via Warp paths
        let handle = tokio::spawn(
            warp::serve(warp::fs::dir("../data/published/")).run(([127, 0, 0, 1], 4321)),
        );

        println!("//spawn web");
        CatalogServer {
            server: handle,
            runtime,
        }
    }

    use tokio::task::JoinHandle;

    #[rstest]
    fn web_fetch(catalog_server: CatalogServer) {
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
        // this is the read-cap for "brunnhilde" from the kitten-catalog
        // to create this test-data run (from the root of the checkout):
        //  - mkdir data/
        //  - cargo run -- publish kitten-catalog/ data/published
        let rcap: ImmutableReadCap =
            "mcap0rwedkkhZUU4LIEBS9VypVCYO6YQrVpkYhazyNtg16Kzhqt4pKhRGjXNLLEhdYG-vZ"
                .try_into()
                .unwrap();
        let id: ImmutableIdentifier = (&rcap).into();
        let res = catalog.fetch_metadata(&id).unwrap();
        assert!(rcap.verify.corresponds_to(&res));
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
            let tmpd = tempdir()?;

            let mut catalogs: Vec<Box<dyn magic_cap::ImmutableCatalog<'_>>> = vec![
                std::boxed::Box::new(magic_cap::ImmutableDirectoryCatalog::create(tmpd.as_ref().to_path_buf())?),
            ];
            let publish_dir = tmpd.path().to_str().unwrap();
            let publisher: Box<dyn magic_cap::ImmutablePublisher<'_>> =
                magic_cap::connect_publisher(publish_dir)?;

            let plain = tmpd.path().join("plain");
            println!("creating plain file at {:?}",plain);
            {
                let mut tmp = File::create(&plain)?;
                let _written_amount = tmp.write(s.as_bytes())?;
            }  // close tmp
            println!("finished writing to tmp");
            let mut output = vec!();
            main_encrypt(&mut output, &plain, publisher, 4096).unwrap();

            let capstr: &str = std::str::from_utf8(&output)?.trim_end();
            let round = tmpd.path().join("decrypted");

            // turn this into a Verify Cap and confirm the ciphertext
            let mut output = vec!();
            main_reduce(&mut output, capstr)?;
            let verifycap = std::str::from_utf8(&output)?.trim_end();
            main_verify(verifycap, &mut catalogs).unwrap();

            // "reducing" a Verify Cap is a no-op
            let mut output = vec!();
            main_reduce(&mut output, verifycap).unwrap();
            assert_eq!(String::from_utf8(output).unwrap().trim(), verifycap);

            // confirm that "decrypt" can turn back into plaintext
            let immutable_read_cap = ImmutableReadCap::from_str(capstr).unwrap();
            // XXX why does this test pass? The println at the top certainly runs! Something is wrong here!
            main_decrypt(&immutable_read_cap, &mut catalogs, &Some(round.clone())).unwrap();

            let mut og = String::new();
            let mut other = String::new();
            File::open(plain)?.read_to_string(&mut og)?;
            File::open(round)?.read_to_string(&mut other)?;

            assert_eq!(og, other);
        }
    }
}
