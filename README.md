## Plumaa

**Plumaa is a [Safe Wallet](https://app.safe.global/) module that enables SHA PKCS1.5 signatures to be used as signer mechanism for EVM transactions**.

> [!IMPORTANT]  
> Project is unmantained. This is a deliberate decision since the design became too convoluted and the team didn't feel comfortable shipping this code without getting it audited first.

> [!WARNING]  
> Although coverage is great and tests are passing, consider this code as unsafe to use since it hasn't been audited and also involves complex interactions between signatures.

## Getting started

Install dependencies with

```bash
forge install
```

To run tests, you'll need to setup the /keys directory. Follow its [README](./keys/README.md) for more information.

Once keys are set, run tests with:

```bash
forge clean && forge test
```

### Keys

Information about how private keys work and are used for testing can be found at the [keys directory](./keys/README.md)
