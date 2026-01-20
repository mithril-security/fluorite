use std::marker::PhantomData;

use anyhow::anyhow;
use dryoc::sign::SigningKeyPair;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::cbor;
pub trait MsgEnum:
    Serialize + DeserializeOwned + std::fmt::Debug + Clone + Msg<MsgEnum = Self>
{
    fn new_keypair() -> MessageKeyPair<Self> {
        MessageKeyPair {
            inner: SigningKeyPair::gen_with_defaults(),
            _msg: PhantomData,
        }
    }
}

pub trait Msg: Clone + TryFrom<Self::MsgEnum> + Into<Self::MsgEnum> {
    type MsgEnum: MsgEnum;

    fn as_enum(&self) -> Self::MsgEnum {
        self.clone().into()
    }
}

impl<T: MsgEnum> Msg for T {
    type MsgEnum = Self;
}

#[derive(Clone)]
pub struct MessageKeyPair<M: MsgEnum> {
    inner: SigningKeyPair<dryoc::types::StackByteArray<32>, dryoc::types::StackByteArray<64>>,
    _msg: PhantomData<M>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageVerifyingKey<M: MsgEnum> {
    inner: dryoc::sign::PublicKey,
    _msg: PhantomData<M>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedMessage<M: Msg> {
    inner: dryoc::sign::VecSignedMessage,
    #[serde(skip)]
    _msg: PhantomData<M>,
}

impl<M: MsgEnum> MessageVerifyingKey<M> {
    pub fn verify<MM: Msg<MsgEnum = M>>(&self, msg: &SignedMessage<MM>) -> anyhow::Result<MM> {
        msg.inner.verify(&self.inner)?;
        let (_, msg) = msg.inner.clone().into_parts();
        let msg: M = cbor::from_slice(&msg)?;
        let msg = MM::try_from(msg).map_err(|_| anyhow!("Bad variant"))?;
        Ok(msg)
    }
}
impl<M: MsgEnum> MessageKeyPair<M> {
    pub fn verifying_key(&self) -> MessageVerifyingKey<M> {
        MessageVerifyingKey {
            inner: self.inner.public_key.clone(),
            _msg: PhantomData,
        }
    }
    pub fn sign<MM: Msg<MsgEnum = M>>(&self, msg: &MM) -> anyhow::Result<SignedMessage<MM>> {
        let msg: M = msg.clone().into();
        Ok(SignedMessage {
            inner: self.inner.sign_with_defaults(&cbor::to_vec(&msg)?[..])?,
            _msg: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use derive_more::derive::{From, TryInto};
    use serde::{Deserialize, Serialize};

    use super::{Msg, MsgEnum};

    #[derive(Serialize, Deserialize, Clone, Debug)]
    struct A {}
    #[derive(Serialize, Deserialize, Clone, Debug)]
    struct B {}
    #[derive(TryInto, From, Serialize, Deserialize, Clone, Debug)]
    enum TestMsg {
        A(A),
        B(B),
    }

    impl MsgEnum for TestMsg {}

    impl Msg for A {
        type MsgEnum = TestMsg;
    }
    impl Msg for B {
        type MsgEnum = TestMsg;
    }
    #[test]
    fn test_a() -> anyhow::Result<()> {
        let testmsg_keypair = TestMsg::new_keypair();
        let test_verify_key = testmsg_keypair.verifying_key();
        let sign_msg = testmsg_keypair.sign(&A {})?;
        let gen_msg = A {}.as_enum();
        let x = testmsg_keypair.sign(&gen_msg)?;
        let a = test_verify_key.verify(&x)?;

        // let sign_msg =
        let msg_a = test_verify_key.verify(&sign_msg)?;

        Ok(())
    }
}
