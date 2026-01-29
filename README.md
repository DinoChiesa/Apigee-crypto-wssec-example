# Demonstration of Apigee crypto wsSec

Recently, Google has added support for WS-Security signing and validating, using RSA keys, into the Apigee runtime.
This is documented [here](https://docs.cloud.google.com/apigee/docs/api-platform/reference/javascript-object-model#cryptoobjectreference-cryptowsSecRsaSign)

You can access this capability from within a JavaScript callout.

This repo provides some examples showing how to use that new feature.


A WS-Security signed document usually follows this structure:

```xml
<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soap:Header>
    <wssec:Security
        xmlns:wssec="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soap:mustUnderstand="1">
      <wsu:Timestamp wsu:Id="TS-100">
        <wsu:Created>2026-01-29T02:54:51Z</wsu:Created>
        <wsu:Expires>2026-01-29T02:56:51Z</wsu:Expires>
      </wsu:Timestamp>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <Reference URI="#Body-102">...
        </SignedInfo>
        <SignatureValue>kn7...</SignatureValue>
        <KeyInfo>...</KeyInfo>
      </Signature>
    </wssec:Security>
  </soap:Header>
  ....
```

That is, there's a `soap:Header`, and within that a `wssec:Security` element,
which contains a `Signature`. The `Signature` element provides information about
how the signature has been computed, and information about the key used for
signing.  While different algorithms and keys can be used, this capability
within Apigee provides support only for RSA signing at this time.


## License and Copyright

This material is [Copyright (c) 2026 Google LLC](./NOTICE).
and is licensed under the [Apache 2.0 License](LICENSE).


## Disclaimer

This example is not an official Google product, nor is it part of an
official Google product.


## Work in Progress

This is a work in progress. Current examples show _signing_.  Future expansions will show validation.


## Using the examples

To use these examples, you need these pre-requisities:

1. [Provision Apigee X](https://cloud.google.com/apigee/docs/api-platform/get-started/provisioning-intro)

2. Configure [external access](https://cloud.google.com/apigee/docs/api-platform/get-started/configure-routing#external-access)
   for API traffic to your Apigee X instance

3. The following tools are available in your terminal's $PATH
    - [gcloud CLI](https://cloud.google.com/sdk/docs/install)
    - [apigeecli](https://github.com/apigee/apigeecli)

   Google Cloud Shell has these preconfigured.


Deploy the API proxy bundle this way:

```
TOKEN=$(gcloud auth print-access-token)

apigeecli apis create bundle -f apiproxy \
  --name crypto-wssec -o $ORG_NAME --token $TOKEN

apigeecli apis deploy --wait --name crypto-wssec \
  --ovr --org $ORG_NAME --env $ENV_NAME --token $TOKEN
```

On Windows, you can run the equivalent commands.

```
$TOKEN = $(gcloud auth print-access-token)

apigeecli apis create bundle -f apiproxy `
  --name crypto-wssec -o $ORG_NAME --token $TOKEN

apigeecli apis deploy --wait --name crypto-wssec `
  --ovr --org $ORG_NAME --env $ENV_NAME --token $TOKEN
```



## Signing examples

The signing examples all use the same base SOAP document, and sign it, using the same RSA key and certificate.
I generated the RSA key and cert using openssl:

```
# requires openssl 1.1.1 or newer
openssl genpkey  -algorithm rsa -pkeyopt  rsa_keygen_bits:2048 -out rsa-privatekey.pem
openssl req \
    -new \
    -x509 \
    -sha256 \
    -days 3650 \
    -key rsa-privatekey.pem \
    -out issuer-certificate-20260127.pem \
    -subj "/C=US/ST=Washington/L=Kirkland/O=Google LLC/OU=Apigee/CN=Apigee Demonstration 20260127 Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "extendedKeyUsage=serverAuth,clientAuth" \
    -addext "subjectKeyIdentifier=hash"
```

And then embedded that sample key and cert into the Apigee proxy bundle. This IS NOT THE CORRECT WAY TO MANAGE KEYS.
Certificates are not secret - it's ok to embed a cert into any public document.

But you should never embed a private key into a configuration file that is openly readable. **This is ok only for
demonstration purposes**.


### Variations in Signing

The various examples show variations in how the signed document is constructed. The behavior for some of the parameters is "obvious".
For example if you set the expiry of the signature to 2 minutes or 10 minutes, that's really clear. It just changes the Expires element in the Timestamp element in the SOAP Header.

But the behavior of other parameters is perhaps not as obvious.  In particular, the `key_identifier_type` parameter alters the way the `KeyInfo`  element appears in the final signed document.

The code in the Javascript callout looks like this:
```
var unsigned = context.getVariable('request.content');
var signed = crypto.wsSecRsaSign(unsigned, {
  private_key: '{private.key.pem}',
  certificate: '{public.cert.pem}',
  key_identifier_type: '{desired_key_identifier_type}',
  signing_method: 'rsa-sha256',
  digest_method: 'sha256',
  expires_in: '300s'
});
context.setVariable('signed_soap', signed);
```

...where `desired_key_identifier_type` is a context variable that holds one of the following values:
- `BST_DIRECT_REFERENCE`
- `X509_CERT_DIRECT`
- `ISSUER_SERIAL`
- `THUMBPRINT`
- `RSA_KEY_VALUE`


The samples here show the result of these options.


### `key_identifier_type`: `BST_DIRECT_REFERENCE`

Request this variant of the signature like this:
```
curl -i $apigee/crypto-wssec/t1
```

The output signed document will have a `KeyInfo` element that looks like so:

```
  <KeyInfo>
    <wssec:SecurityTokenReference>
      <wssec:Reference URI="#ST-101"
        ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
    </wssec:SecurityTokenReference>
  </KeyInfo>
```

And there will be another element elsewhere in the header that provides the `BinarySecurityToken`:
```
<wssec:BinarySecurityToken
  EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
  ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
  wsu:Id="ST-101">MIIEKjCCAxKgAwIB...

```

### `key_identifier_type`: `X509_CERT_DIRECT`

Request this variant of the signature like this:
```
curl -i $apigee/crypto-wssec/t2
```

The output signed document will have a `KeyInfo` element that looks like so:

```
  <KeyInfo>
    <X509Data>
      <X509Certificate>M....

```


### `key_identifier_type`: `ISSUER_SERIAL`

Request this variant of the signature like this:
```
curl -i $apigee/crypto-wssec/t3
```

The output signed document will have a `KeyInfo` element that looks like so:

```
  <KeyInfo>
    <wssec:SecurityTokenReference wsu:Id="STR-102">
      <X509Data>
        <X509IssuerSerial>
          <X509IssuerName>...C=US,ST=...</X509IssuerName>
          <X509SerialNumber>241....</X509SerialNumber>
        </X509IssuerSerial>
      </X509Data>
    </wssec:SecurityTokenReference>
  </KeyInfo>
```



### `key_identifier_type`: `THUMBPRINT`

Request this variant of the signature like this:
```
curl -i $apigee/crypto-wssec/t4
```

The output signed document will have a `KeyInfo` element that looks like so:

```
  <KeyInfo>
    <wssec:SecurityTokenReference>
      <wssec:KeyIdentifier
        ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">...</wssec:KeyIdentifier>
    </wssec:SecurityTokenReference>
  </KeyInfo>
```



### `key_identifier_type`: `RSA_KEY_VALUE`

Request this variant of the signature like this:
```
curl -i $apigee/crypto-wssec/t5
```

The output signed document will have a `KeyInfo` element that looks like so:

```
  <KeyInfo>
    <KeyValue>
      <RSAKeyValue>
        <Modulus>A.....</Modulus>
        <Exponent>AQAB</Exponent>
      </RSAKeyValue>
    </KeyValue>
  </KeyInfo>
```


## Validation examples

The validation examples all work similarly: they obtain a signed document, and then validate it using
either the certificate that is  in the document, or a certificate provided by the validator (Apigee).

The basic usage is:

```
var isValid = crypto.wsSecRsaValidate(signed, options);
```

...where `signed` is a string containing the XML of the WS-Security signed
document, and `options` is a JS object containing options for the validation.
For example,

```js
var options =  {
    certificate : '{public.cert.pem}',
    ignore_certificate_expiry: 'false',
    signing_method: 'rsa-sha256'
  };

// -or-

var options =  {
    accept_thumbprints: '{public.cert.thumbprint.sha1.hex}',
    ignore_certificate_expiry: 'false',
    signing_method: 'rsa-sha256'
  };

```


Whether you must use `certificate` or `accept_thumbprints` depends on the `KeyInfo` element in the signed document:

- When `KeyInfo` in the signed document includes `X509Data/X509Certificate`, or
  `<wssec:SecurityTokenReference>` pointint to `BinarySecurityToken`, then the
  validator can use the certificate embedded within the signed document.

- When `KeyInfo` in the signed document points to an issuer/Serial or a thumbprint, the
  validator must explicitly provide the certificate used to validate.


Some concrete examples follow:

### `KeyInfo` contains a `SecurityTokenReference`

Request validation with this variant, like this:

```
curl -i "${apigee}/crypto-wssec/validate/t1"
```

On success, you will see the signed document in output.

When validating a signature using the certificate that is embedded in the signed
document, it is essential to validate the thumbprint of the certificate as
well. This second step insures that the signed document has been signed with a
certificate that the validator trusts. If the validator did not check the
thumbprint, then... any document signed with any key, would be treated as valid.
And you don't want that.

Validation of the thumbprint is done by the `crypto.wsSecRsaValidate()` method,
when you pass a `accept_thumbprints` field in the options. This is done in the
JS-Validate step like so:

```js
// In some cases, the validator must explicitly supply the cert.
var specifyCert = context.getVariable('validator-provides-the-certificate');
if (specifyCert) {
  options.certificate = '{public.cert.pem}';
}
else {
  options.accept_thumbprints = '{public.cert.thumbprint.sha1.hex}';
}
```



### `KeyInfo` contains `<X509Data>/<X509Certificate>`


Request validation with this variant, like this:

```
curl -i "${apigee}/crypto-wssec/validate/t2"
```


### `KeyInfo` contains `X509IssuerSerial`

Request this variant of the validation like this:
```
curl -i "${apigee}/crypto-wssec/validate/t3"
```

A thumbprint is not enough to validate a signature. The validator needs a
certificate, or a public key.  In this case, the logic in the API proxy
explicitly provides the certificate to use for validation. It does this in the
logic within the JS-Validate step:

```js
// In some cases, the validator must explicitly supply the cert.
var specifyCert = context.getVariable('validator-provides-the-certificate');
if (specifyCert) {
  options.certificate = '{public.cert.pem}';
}
else {
  options.accept_thumbprints = '{public.cert.thumbprint.sha1.hex}';
}
```


If the logic _did not_ provide the certificate, you would see this error:
```xml
<error>
  <reason>certificate is missing</reason>
</error>
```


### `KeyInfo` contains `wssec:KeyIdentifier` with a value of `ThumbprintSHA1`

Request this variant of the validation like this:
```
curl -i "${apigee}/crypto-wssec/validate/t4"
```

A thumbprint is not enough to validate a signature. The validator needs a certificate, or a public key.
As in case t3, the logic in the API proxy provides the certificate to use for validation.

### `KeyInfo` contains `<KeyValue>/<RSAKeyValue>`

Request this variant of the validation like this:
```
curl -i "${apigee}/crypto-wssec/validate/t5"
```

This is not supported by the validator, at this time. So you will see an error:

```xml
<error>
  <reason>No suitable child element of KeyInfo</reason>
</error>
```

At this time, this is expected.


## Support

If you find issues with the sample, file a ticket here on Github.  Keep in mind that there is no
service level agreement (SLA) for responses to these issues. Assume all
responses are on an ad-hoc, volunteer basis.

If you simply have questions,  ask on the [Apigee discussion
forum](https://discuss.google.dev/c/google-cloud/cloud-apigee/104).
Apigee experts regularly check that forum.


Apigee customers should use [formal support
channels](https://cloud.google.com/apigee/support) for Apigee product related
concerns.
