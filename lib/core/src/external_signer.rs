use lwk_wollet::elements::pset::PartiallySignedTransaction;
use tokio::sync::mpsc;

use crate::error::PaymentError;

pub struct ExternalSigner {
    sender: mpsc::Sender<PartiallySignedTransaction>,
    receiver: mpsc::Receiver<PartiallySignedTransaction>,
}

impl ExternalSigner {
    pub async fn request_sig(&mut self, pset: &mut PartiallySignedTransaction) -> Result<(), PaymentError> {
        self.sender.send(pset.clone()).await.map_err(|e| PaymentError::Generic { err: format!("{:?}", e) })?;
        *pset = self.receiver.recv().await.unwrap();

        Ok(())
    }

    pub async fn wait_for_request(&mut self) -> Result<Option<PartiallySignedTransaction>, PaymentError> {
        Ok(self.receiver.recv().await)
    }

    pub async fn provide_sig(&mut self, pset: PartiallySignedTransaction) -> Result<(), PaymentError> {
        self.sender.send(pset).await.map_err(|e| PaymentError::Generic { err: format!("{:?}", e) })?;
        Ok(())
    }
}

pub fn make_channel() -> (ExternalSigner, ExternalSigner) {
    let (sender_a, receiver_a) = mpsc::channel(16);
    let (sender_b, receiver_b) = mpsc::channel(16);

    (ExternalSigner {sender: sender_a, receiver: receiver_b}, ExternalSigner {sender: sender_b, receiver: receiver_a})
}