use super::super::{
    Direction, Error, Kind,
    cipher::{Cipher, SoftwareCipher},
    record::Records,
};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};
use zeroize::Zeroizing;

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("software cipher must complete without suspension"),
    }
}

#[test]
fn async_cipher_preserves_independent_record_vectors_and_rejects_mutations() {
    let fixture = super::fixture();
    let root: [u8; 32] = hex::decode(fixture.root_hex).unwrap().try_into().unwrap();
    let id = hex::decode(fixture.session_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    for stream in fixture.streams {
        let direction = if stream.direction == 1 {
            Direction::Request
        } else {
            Direction::Response
        };
        let number = stream.number.parse().unwrap();
        let mut writer =
            Records::<SoftwareCipher>::new(&root, &id, number, direction, super::header()).unwrap();
        let mut decoder =
            Records::<SoftwareCipher>::new(&root, &id, number, direction, super::header()).unwrap();
        for record in stream.records {
            let kind = Kind::try_from(record.kind).unwrap();
            let content = hex::decode(record.plaintext_hex).unwrap();
            let mut encoded = hex::decode(record.encoded_hex).unwrap();
            assert_eq!(ready(writer.seal_async(kind, &content)).unwrap(), encoded);
            assert_eq!(
                ready(decoder.open_async(&mut encoded)).unwrap(),
                (kind, content.as_slice())
            );
        }
        assert_eq!(decoder.complete(), Ok(()));
    }
    let encoded = Records::new(&root, &id, 0, Direction::Request, super::header())
        .unwrap()
        .seal(Kind::Metadata, b"headers")
        .unwrap();
    for offset in 0..encoded.len() {
        let mut decoder =
            Records::<SoftwareCipher>::new(&root, &id, 0, Direction::Request, super::header())
                .unwrap();
        let mut altered = encoded.clone();
        altered[offset] ^= 1;
        assert!(ready(decoder.open_async(&mut altered)).is_err());
        assert_eq!(
            ready(decoder.open_async(&mut encoded.clone())),
            Err(Error::Closed)
        );
    }
}

struct SuspendedCipher;
impl Cipher for SuspendedCipher {
    fn from_key(_: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        Ok(Self)
    }
    async fn encrypt(&mut self, _: [u8; 12], _: &[u8], _: &mut [u8]) -> Result<[u8; 16], Error> {
        std::future::pending().await
    }
    async fn decrypt(&mut self, _: [u8; 12], _: &[u8], _: &mut [u8]) -> Result<(), Error> {
        std::future::pending().await
    }
}

struct SuspendedDecryptCipher(SoftwareCipher);
impl Cipher for SuspendedDecryptCipher {
    fn from_key(key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        Ok(Self(SoftwareCipher::from_key(key)?))
    }
    async fn encrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        self.0.encrypt(nonce, aad, plaintext).await
    }
    async fn decrypt(&mut self, _: [u8; 12], _: &[u8], _: &mut [u8]) -> Result<(), Error> {
        std::future::pending().await
    }
}

#[test]
fn dropped_crypto_futures_close_the_direction_without_reusing_a_nonce() {
    let mut outgoing =
        Records::<SuspendedCipher>::new(&[1; 32], &[2; 32], 0, Direction::Request, super::header())
            .unwrap();
    {
        let future = outgoing.seal_async(Kind::Metadata, b"headers");
        let mut future = std::pin::pin!(future);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert_eq!(
        ready(outgoing.seal_async(Kind::Metadata, b"headers")),
        Err(Error::Closed)
    );
    let mut encoded = Records::new(&[1; 32], &[2; 32], 0, Direction::Response, super::header())
        .unwrap()
        .seal(Kind::Metadata, b"headers")
        .unwrap();
    let mut incoming = Records::<SuspendedCipher>::new(
        &[1; 32],
        &[2; 32],
        0,
        Direction::Response,
        super::header(),
    )
    .unwrap();
    {
        let future = incoming.open_async(&mut encoded);
        let mut future = std::pin::pin!(future);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert_eq!(ready(incoming.open_async(&mut encoded)), Err(Error::Closed));
}

#[test]
fn dropped_decode_future_discards_partial_state_without_emitting_plaintext() {
    let (mut session, mut server) = super::sessions([1; 32], [2; 32]);
    let mut request = session.request_with::<SuspendedDecryptCipher>().unwrap();
    let mut start = ready(request.seal_async(Kind::Metadata, b"request")).unwrap();
    let (_, mut server, _) = server
        .accept_start(request.number(), &mut start, 0)
        .unwrap();
    let mut decoder = super::super::ResponseDecoder::new(request);
    let metadata = server.seal(Kind::Metadata, b"headers").unwrap();
    ready(decoder.push_async(&metadata, 0, |_, _| Ok(()))).unwrap();
    let encoded = server.seal(Kind::Data, b"body").unwrap();
    let mut emitted = false;
    {
        let future = decoder.push_async(&encoded, 0, |_, _| {
            emitted = true;
            Ok(())
        });
        let mut future = std::pin::pin!(future);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(!emitted);
    assert_eq!(
        ready(decoder.push_async(&[], 0, |_, _| panic!("closed decoder emitted"))),
        Err(Error::Closed)
    );
    assert_eq!(decoder.finish(), Err(Error::Closed));
}

struct YieldingDecryptCipher(SoftwareCipher);
impl Cipher for YieldingDecryptCipher {
    fn from_key(key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        Ok(Self(SoftwareCipher::from_key(key)?))
    }
    async fn encrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        self.0.encrypt(nonce, aad, bytes).await
    }
    async fn decrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> Result<(), Error> {
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        self.0.decrypt(nonce, aad, bytes).await
    }
}

#[test]
fn session_close_and_async_cancel_preserve_independent_admitted_directions() {
    for close_at in 0..4 {
        for cancel in [false, true] {
            let (mut client, mut server_session) = super::sessions([1; 32], [2; 32]);
            let mut request = client.request_with::<YieldingDecryptCipher>().unwrap();
            let mut start = ready(request.seal_async(Kind::Metadata, b"request")).unwrap();
            let (mut incoming, mut outgoing, _) =
                server_session.accept_start(0, &mut start, 0).unwrap();
            let (mut upload, mut response) = request.split();
            if close_at == 0 {
                client.close();
                server_session.close();
            }
            let headers = outgoing.seal(Kind::Metadata, b"headers").unwrap();
            ready(response.push_async(&headers, 0, |_, _| Ok(()))).unwrap();
            if close_at == 1 {
                client.close();
                server_session.close();
            }
            let body = outgoing.seal(Kind::Data, b"response body").unwrap();
            let mut emitted = Vec::new();
            {
                let future = response.push_async(&body, 0, |_, bytes| {
                    emitted.extend_from_slice(bytes);
                    Ok(())
                });
                let mut future = std::pin::pin!(future);
                let mut context = Context::from_waker(Waker::noop());
                assert!(future.as_mut().poll(&mut context).is_pending());
                if close_at == 2 {
                    client.close();
                    server_session.close();
                }
                if !cancel {
                    assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(())));
                }
            }
            if close_at == 3 {
                client.close();
                server_session.close();
            }
            assert!(matches!(client.request(), Err(Error::Closed)));
            if cancel {
                assert!(emitted.is_empty());
                assert_eq!(
                    ready(
                        response.push_async(&body, 0, |_, _| panic!("cancelled response resumed"))
                    ),
                    Err(Error::Closed)
                );
            } else {
                assert_eq!(emitted, b"response body");
                let end = outgoing.seal(Kind::Finished, &[]).unwrap();
                let future = response.push_async(&end, 0, |_, _| Ok(()));
                let mut future = std::pin::pin!(future);
                let mut context = Context::from_waker(Waker::noop());
                assert!(future.as_mut().poll(&mut context).is_pending());
                assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(())));
            }
            // Closing either session or cancelling the response must not erase
            // the separately owned, already admitted upload key.
            let mut body = ready(upload.seal_async(Kind::Data, b"upload body")).unwrap();
            assert_eq!(incoming.open(&mut body).unwrap().1, b"upload body");
            let mut end = ready(upload.seal_async(Kind::Finished, &[])).unwrap();
            incoming.open(&mut end).unwrap();
            assert_eq!(incoming.complete(), Ok(()));
            assert_eq!(
                response.finish(),
                if cancel { Err(Error::Closed) } else { Ok(()) }
            );
        }
    }
}
