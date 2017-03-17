# safetycheck

Command line utility for verifying [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) from Google's SafetyNet API

## Installation

Set `GOPATH` as necessary, then:

```
go install github.com/kianga/safetycheck/cmd/safetycheck
```

## Usage

```
$ safetycheck < good-token.txt
{"apkCertificateDigestSha256":["K64XBz2c/rGGr8msokWAdJeevhYZztQ6S7buXfdSu4o="],"apkDigestSha256":"EC6DSwK8ODHyAc6uRpLf0QqBZkHpW7pOyJP+aVeMyv4=","apkPackageName":"com.example.package","basicIntegrity":true,"ctsProfileMatch":true,"extension":"CQHxcA1H0//M","nonce":"DMnSi/ya8fM0PLslPaHTZg==","timestampMs":1489726139356}
(exit code 0)

$ safetycheck < bad-token.txt
2017/03/17 11:32:53 Failed to validate token: Parse error: crypto/rsa: verification error
(exit code 1)
```

## Dependencies

* [jwt-go](https://github.com/dgrijalva/jwt-go)
