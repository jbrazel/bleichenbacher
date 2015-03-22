This code connects to a remote SSL service, and determines whether the SSL implementation is susceptible to Bleichenbacher's adaptive chosen-ciphertext attack, or the Klima-Pokorny-Rosa adaptive chosen-ciphertext attack.

The code will print a simple 'yes'/'no' as to whether the remote implementation is open to the KPR attack. In the case of Bleichenbacher's attack, there are four scenarios:

a) the SSL service is not vulnerable.
b) the SSL service returns an error only when the PKCS padding is incorrect (level 3). This makes the service enormously susceptible to the attack, and will take on averageabout 8000 attempts to get the first 'hit', and then 512-1024 attempts to crack the session key depending on its length (i.e. it's a walk in the park, the server is horribly broken, and no-one is safe).
c) the SSL service returns an error if the PKCS padding is incorrect, _OR_ the decoded seed is of the wrong length (level 2). This implies the same level of difficulty as the KPR attack. Between 10<sup>6 and 10</sup>8 attempts to get the first 'hit', and then 512-1024 to crack the session key (this is somewhat infeasible in the wild, but you might get lucky). Some versions of OpenSSL are vulnerable to level2 bleichenbacher attacks.
d) the SSL service returns an error if the PKCS padding is wrong, the length of the decoded seed is wrong, or the PKCS version in the decoded data is wrong (level 1). This is nigh on impossible to attack.

Usage:

> ssltest {-b | -k} [-d] [-s] [-t timeout] hostname [port\_number](port_number.md)

where:

> -b tests for Bleichenbacher's attack
> -k tests for the KPR attack
> -d switches on debugging
> -t supplies a connection timeout in seconds
> -s switches on smtp tunneling, to test against SSL-enabled SMTP mail servers.

The port number defaults to 443.

This code only tests for the flaws. It doesn't exploit them. Sorry.