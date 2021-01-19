Thales payShield 9000 Interface
===============================

`hsmxs` is Thales 9000 command library and HTTP REST interface in Erlang. It can be used for establishing specialized application-level security schemes, especially for mobile applications.

This document assumes that the reader has the knowledge of [Thales payShield 9000](https://go.thalesesecurity.com/rs/480-LWA-970/images/payShield-9000-ds.pdf).


Overview
--------

This is an OTP Application for communication with Thales 9000 HSM. It provides a high level HTTP REST-based interface for selected cryptographic services, hiding most of the specifics of Thales commands and communication. It is a simplified version of HSM-Router application, that provides additional features for high-available traffic management to multiple HSM nodes.

REST interface is JSON-based and defined in [yaml specification](https://github.com/astef7/hsmxs/blob/master/hsmxs-api-1.0.0.yaml). WEB server is implemented using embedded [elli HTTP Library](https://github.com/elli-lib/elli). Requests conforming to the yaml specification can be sent by any client (e.g. Python, Java). For convenience (and eunit testing purposes), a simple client `rest_client.erl` is provided.

HSM communication
-----------------

Communication with HSM can use both TCP and UDP transports. By default, TCP is used.

Communication over TCP connection is fully asynchronous, with two separate processes involved: the sender responsible for sending requests and receiver responsible for handling responses. Due to the asynchronous nature of such communication, sender and receiver share a simple ETS table for request/response correlation. Both sender and receiver are under common supervisor control.

REST Services
-------------

HTTP REST interface provides the following services:
- generation of VISA PVV (`set-pin-pvv`)
- verification of VISA PVV (`check-pin-pvv`)
- generation of VISA Dynamic CVV (`generate-dcvv`)
- verification of VISA Dynamic CVV (`check-dcvv`)
- symmetric encryption/decryption (with HSM keys, `encrypt-dek` and `decrypt-dek`)
- import of client-generated 3DES/AES key under HSM LMK for establishing session key. Client key is encrypted under pre-established RSA key (`set-session-key`)
- generation of 3DES/AES key for export to the client. Key is encrypted under previously established session key (`generate-bkey`)

Message definitions are provided in [yaml specification](https://github.com/astef7/hsmxs/blob/master/hsmxs-api-1.0.0.yaml).

These simple services set foundation for establishing HSM-managed security scheme for mobile applications. Such scheme works on the following basis:

(1) During mobile application provisioning, backend generates new RSA key pair on HSM (EI command) and stores this under specific 'RSA offset'. Mobile application is equipped with RSA public key and offset.

(2) Whenever mobile application is sending PIN data, it:
  - generates temporary 3DES key
  - builds appropriate pinblock
  - encrypts pinblock with 3DES key
  - encrypts 3DES key under its RSA public key
  - sends pair {keyBlock,pinBlock} to the backend, probably with some accompanying data items
  Receiving such pin-data packet, backend:
  - imports 3DES key encrypted under RSA to TPK encrypted under LMK
  - uses encrypted pinblock together with TPK for further pin verification procedure, such as PVV verification.

(3) Establishing session key: mobile application sets session key by the following procedure:
- generates temporary 3DES/AES key
- encrypts it with its RSA public key
- sends session request to the backend
Backend imports this key as TEK/DEK under LMK encryption
Starting from that moment, mobile application and backend has shared symmetric encryption key

HSM Commands
------------
The following Thales commands are used:
- EI (RSA pair generation),
- GI (key import from RSA to LMK encryption),
- A0 (key generation)
- M0 (symmetric encryption)
- M2 (symmetric decryption)
- N0 (random number generation)
- JC (conversion from pinblock/TPK to pin/LMK)
- DG (VISA PVV generation)
- DC (VISA PVV verification)
- PM (VISA dynamic CVV generation/verification)

HSM commands can use either keyblock or variant LMK keys.

Additional libraries
--------------------
Apart from HSM communication support, application offers methods for pinblock formatting (`pinblk.erl`) and basic symmetric cryptography used for pinblocks (`cryptoxs.erl`). Pinblock functions supports:
- ISO 9564-1 Format 0 / ANSI X9.8
- ISO 9564-1 Format 1
- ISO 9564-1 Format 3

Configuration
-------------
Configuration is placed in the standard sys.config file.

Relevant sections are `hsm` and `rest`:
```
 {hsm,[{buff_max,31000},
       {ip,{10,10,104,25}},
       {port,1500}]},
       
 {rest,[{port,8087}]}
```

`buff_max` controls maximum load on the HSM buffer. This is mandatory mechanism when accessing Thales HSM. `hsmxs` tracks buffer usage with each command exchanged with HSM. If sending the command would exceed the limit, `hsmxs` will respond with `{error,buff_overflow}`. You can lower the default value, however trying to set value higher than 32000 will be superseded with this value anyway.

`ip` and `port` are HSM address parameters.

`rest` section with its `port` param describes the `elli` WEB server port established on the local interface. By default, the WEB server is started on 8087 port.

As you may know, eunit used within rebar3 does not automatically load sys.config parameters on application startup. To overcome this, you will find simple macros checking `-ifdef(EUNIT).` to load relevant params from sys.config in such cases.

Basic Usage
-----------
It is assumed you have access to Thales HSM device and sys.config params are properly set.

Starting `hsmxs` application with rebar3:

```
~/hsmxs$ rebar3 shell
```

After `hsmxs` is started, you can test it using any tool sending REST/Json messages conforming to [yaml specification](https://github.com/astef7/hsmxs/blob/master/hsmxs-api-1.0.0.yaml).

It is also possible to use a simple REST client module [elli_client.erl](). It consists of pre-configured code to invoke certain `hsmxs` services.

Some examples:

```
17> {ok,Pvv} = elli_client:test(pvv_generate).
18> {ok} = elli_client:test(pvv_check,Pvv).

...

20> {ok,Dcvv} = elli_client:test(dcvv_generate).
21> {ok} = elli_client:test(dcvv_check,Dcvv).

```

Asn.1 usage
-----------
`hsmxs` uses [Erlang ASN.1](http://erlang.org/doc/apps/asn1/asn1_getting_started.html). However this usage is very narrow however and is restricted to parsing Thales-generated RSA public key data. Thales uses non-standard encoding for this.

Build
-----
    $ rebar3 compile

Tests
-----
    $ rebar3 eunit --cover --dir="test"

Coverage
--------
    $ rebar3 cover --verbose

Credits
-------
Artur Stefanowicz, artur.stefanowicz7@gmail.com

Licence
-------
Apache 2.0
