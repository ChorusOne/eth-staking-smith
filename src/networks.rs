#[derive(clap::ValueEnum, Clone, Hash, Eq, PartialEq)]
pub enum SupportedNetworks {
    Mainnet,
    Holesky,
    // These are legacy networks they are supported on best effort basis
    Prater,
    Goerli,
}

impl std::fmt::Display for SupportedNetworks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SupportedNetworks::Mainnet => "mainnet",
            SupportedNetworks::Holesky => "holesky",
            SupportedNetworks::Prater => "goerli",
            SupportedNetworks::Goerli => "goerli",
        };
        write!(f, "{}", s)
    }
}
