# Letting Spirits Roam the DHT

The idea here is that you can create node ids that look random to everyone, but
with a private key you can check if you are meant to find it.
These nodes can then freely roam the DHT, and you can discover them as you
casually do lookups without them needing to direct communicate their existance
with you.

So its basically just way of signalling in a public place, which anyone aware of
your public key can signal to you through. (i.e this is assumed to be embedded
in publically avaliable software)
The goal is not to ever find all the signals, but to find some over time as you
passively observe.

## Usage

Setup:
```
virtualenv -p python3 .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then you can use modify either `identify-curve25519.py` or `identify-custom.py`
to your needs, or run them directly to them them out:
```
python3 identify-curve25519.py
python3 identify-custom.py ./curves/120bit-prime.json
```

## Details

The scheme here is essentially ECDH with a custom small curve (generated with
ecgen[1] `ecgen --fp -u -p -r 120`).
The node IDs are of the form: `(public key, partial hash of the secret)`

Where the public key is generated by the node, and the hash is a hash of the
shared secret calculated by doing ECDH with your key.
So you can verify a node ID by extracting the public key from the ID, doing ECDH
and seeing if the partial hash matches what you expected.

To save space I used point compression, the same scheme in [2], and made it so
all the public keys used have even y values, so you don't need to bother wasting
another byte to indicate that.

The length of the partial hash controls the amount of false positives you get,
and the key length you use determines how strong the scheme is against someone
cracking your private key, allowing them to determine which node IDs are valid.
The false positive rate is amount avoiding other people using the same curve as
you but with a different key, or accidentally finding a point that passes the
decompression test.

To work with the mainline bittorrent DHT, this uses 2^120 ECDH keys (roughly
2^60 in strength[3], so weak but more commpute than what you'd want to spend to
break this, probably at least $10,000 based on what you apparently need to break
DES nowadays) and 5 bytes to lower the false positive rate. You can obviously
change these to suite your needs.

Ideally, you'd just use Curve25519 and SHA256 if you have greater than 40 bytes
to spare. But Node IDs in bittorrent are only SHA1, giving just 20 bytes so the
crypto has to be weaker.

This is similar to how alt.anonymous.messages worked, where you'd just try to
decrypt every message in a shared mailbox, but far more simple in purpose. The
scheme here is basically just how you do anonymous messaging with ECC schemes.

## Attacks

*  The scheme might be a bit biased based on what is a valid public key, i.e
   what x values are real. Better curves are probably needed with more x values
   on the curve. You could maybe achieve a better than random chance of guessing
   which nodes are valid this way.
* Cracking your private key, can't do much here, this is a strength trade off.
* Flooding with valid node IDs. Anyone can generate them, so this might be an
  issue depending on application.
* Client behaviour being unique.

## Potential Extentions

* Hashcash your way to extra data being stored. You could overlay part of the
  public key with bytes from the output, getting a bit better usage of the space
  avaliable. Just slow to do this. This is how you'd work with the DHT Security
  Extention that tries to get your node ID to depend on your external IP.
* Alternative things like BLE device names or Wifi SSIDs. This should work with
  both, but you get different amounts of space + but you can get away with
  base64 instead of raw bytes with those.


## References

* [1] https://github.com/J08nY/ecgen
* [2] https://mvalvekens.be/blog/2022/ecc-point-compression.html
* [3] do not quote me on this. I was just using the estimates I kept finding.