#[derive(Debug)]
pub enum BeaconNodeError {
    InvalidBeaconNodeURI,
    ClientConfigurationError,
    NodeCommunicationError,
    Non200Response,
}

/// A trait for types that can be sent to beacon node as-is
/// without transformations
pub trait BeaconNodeExportable {
    /// Export an entity as JSON
    fn export(&self) -> serde_json::Value;

    /// The path at beacon node where to send data
    fn beacon_node_path(&self) -> String;

    /// Send the JSON payload to beacon node
    fn send_beacon_payload(&self, beacon_node_uri: url::Url) -> Result<(), BeaconNodeError> {
        let reqwc = reqwest::blocking::Client::builder()
            .build()
            .map_err(|_| BeaconNodeError::ClientConfigurationError)?;
        let joined_url = beacon_node_uri
            .join(&self.beacon_node_path())
            .map_err(|_| BeaconNodeError::InvalidBeaconNodeURI)?;
        let resp = reqwc
            .post(joined_url)
            .header("Content-Type", "application/json")
            .body(self.export().to_string())
            .send();

        match resp {
            Ok(response) => {
                let code = response.status().as_u16();
                if code != 200 {
                    Err(BeaconNodeError::Non200Response)
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(BeaconNodeError::NodeCommunicationError),
        }
    }
}
