const networks = {
  mainnet: {
    wif: 0x80,
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    }
  },
  testnet: {
    wif: 0xef,
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    }
  }
};

function getNetwork(isTestnet) {
  return networks[isTestnet ? 'testnet' : 'mainnet'];
}

module.exports = {
  networks,
  getNetwork
};
