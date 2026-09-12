# Storage payload pins extracted from the reviewed Ubuntu snapshot lock.
{ fetchurl }:
[
  (fetchurl {
    url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/logsave_1.47.2-3ubuntu4_amd64.deb";
    sha256 = "465cb25b468c5f6e883f3ae46c044506e14cdd1aed539a9cc19ce1be8a31d517";
  })
  (fetchurl {
    url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/libext2fs2t64_1.47.2-3ubuntu4_amd64.deb";
    sha256 = "0c58fa90fcb38c1bcc0dbce47b105c60c990128e0220b087f4513d82499d404e";
  })
  (fetchurl {
    url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/libss2_1.47.2-3ubuntu4_amd64.deb";
    sha256 = "08d28bd0e1402f45c1e7c9b28cc65ec55442876217c9f553e8836c0622a71509";
  })
  (fetchurl {
    url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/e2fsprogs_1.47.2-3ubuntu4_amd64.deb";
    sha256 = "a4343a8c026e1ca8e2e76a5d01abb8c2d6381961a1766b2d2363e3e23cc362ca";
  })
]
