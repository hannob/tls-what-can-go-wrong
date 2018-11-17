TLS - what can go wrong?
========================

RSA Key generation

 * [Debian weak keys](https://wiki.debian.org/SSLkeys)
 * [ROCA](https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
 * Shared prime factors ([mining ps and qs](https://factorable.net/))
 * Shared non-private keys (e.g. using default keys shipped with applications)

RSA encryption handshake

 * [Bleichenbacher](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf), [Klima](https://eprint.iacr.org/2003/052), [ROBOT](https://robotattack.org/) etc. attacks
 * SSLv2 Bleichenbacher attack ([https://drownattack.com/](DROWN))

RSA signature handshake

 * [RSA-CRT bug](https://securityblog.redhat.com/2015/09/02/factoring-rsa-keys-with-tls-perfect-forward-secrecy/) / modexp miscalculation (signature generation)
 * [Bleichenbacher signature forgery](https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html), [BERserk](http://www.c7zero.info/stuff/BERserk_eko10.pdf) (signature verification)

ECDSA / DSA handshake

 * Duplicate r (not found in the wild yet)

Static DH/ECDH handshake

 * [KCI](https://kcitls.org/)

Diffie Hellman

 * [Backdoor parameters](https://eprint.iacr.org/2016/644), some detectable (e.g. non-prime modulus), others not
 * [Logjam](https://weakdh.org/) (paper describes multiple attacks), too small parameters
 * [Ephemeral key reuse with small subgroup parameters](https://www.openssl.org/news/secadv/20160128.txt)
 * [DH/ECDH parameter confusion](https://www.cosic.esat.kuleuven.be/publications/article-2216.ps)

ECDHE

 * [Curveswap](https://eprint.iacr.org/2018/298.pdf)
 * [Invalid Curve attack](https://web-in-security.blogspot.com/2015/09/practical-invalid-curve-attacks.html) / ephemeral key reuse

Finished message

 * Lack of check, also partial lack of check, [Poodle has friends](https://yngve.vivaldi.net/2015/07/14/the-poodle-has-friends/)

CBC/HMAC

 * [BEAST](https://www.youtube.com/watch?v=-BjpkHCeqU0)
 * [Vaudenay's Padding Oracle](https://iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.ps) (impractical due to encrypted error messages)
 * [Canvel's timing oracle](https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1069/1069.pdf)
 * [Lucky Thirteen](http://www.isg.rhul.ac.uk/tls/Lucky13.html), [Lucky Microseconds](https://eprint.iacr.org/2015/1129)
 * [LuckyMinus20](https://web-in-security.blogspot.com/2016/05/curious-padding-oracle-in-openssl-cve.html) (CVE-2016-2107)
 * [POODLE](https://www.openssl.org/~bodo/ssl-poodle.pdf) (SSLv3)
 * Lack of padding check in TLS 1.0 and later ([POODLE-TLS](https://www.imperialviolet.org/2014/12/08/poodleagain.html))
 * Partial padding checks, [More POODLEs in the forest](https://yngve.vivaldi.net/2015/07/14/there-are-more-poodles-in-the-forest/)
 * MACE / Lack of HMAC check, also partial checks [Poodle has friends](https://yngve.vivaldi.net/2015/07/14/the-poodle-has-friends/)

GCM

 * Duplicate or random nonces ([Forbidden attack](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/Joux_comments.pdf), [Nonce-disrespecting adversaries](https://github.com/nonce-disrespect/nonce-disrespect))
 * Lack of ghash check (not found in the wild yet)

Small block size

 * [Sweet32](https://sweet32.info/)

RC4

 * [RC4 Biases](http://www.isg.rhul.ac.uk/tls/), cipher design problem, unfixable

Compression

 * [CRIME](https://en.wikipedia.org/wiki/CRIME) (TLS compression)
 * [BREACH](http://breachattack.com/) (HTTP compression)
 * [TIME](https://www.blackhat.com/eu-13/briefings.html#Beery), [HEIST](https://www.blackhat.com/us-16/briefings/schedule/#heist-http-encrypted-information-can-be-stolen-through-tcp-windows-3379) (TCP window trick, Javascript, timing + HTTP compression)

State machine errors

 * [SMACK](https://mitls.org/pages/attacks/SMACK), SkipTLS
 * [FREAK](https://censys.io/blog/freak)
 * [CCS Injection](http://ccsinjection.lepidum.co.jp/)

HTTP/HTTPS related

 * [SSL Stripping](https://moxie.org/software/sslstrip/)
 * Insecure redirects (e.g. https:// -> http://www. -> https://www.)

Parsing and validation logic issues

 * [Heartbleed](http://heartbleed.com/)
 * [STARTTLS command injection](https://www.kb.cert.org/vuls/id/555316/)
 * Version intolerance, large handshake intolerance, middlebox breakage, ...
 * [Frankencerts](https://www.cs.utexas.edu/~shmat/shmat_oak14.pdf#page=11)
 * [goto fail](https://www.imperialviolet.org/2014/02/22/applebug.html)

Others

 * [Insecure Renegotiation](https://tools.ietf.org/html/rfc5746)
 * [Triple Handshake](https://www.mitls.org/pages/attacks/3SHAKE)
 * [Virtual Host Confusion](https://bh.ht.vc/vhost_confusion.pdf)
 * [Cookie cutter](https://hal.inria.fr/hal-01102259/file/triple-handshakes-and-cookie-cutters-oakland14.pdf)
 * [SLOTH](https://www.mitls.org/pages/attacks/SLOTH)
 * Carry propagation bugs / math bugs (can cause RSA-CRT bug, [Squeezing a key through a carry bit](https://www.youtube.com/watch?v=HaUtPd-x7VM))
