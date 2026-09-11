# This is a generated file.  Do not modify!
# Following are the Debian packages constituting the closure of: ca-certificates iproute2 nftables libc6 libc-bin libcap2 libxml2-16 libstdc++6 libgcc-s1 zlib1g libtirpc3t64 libtirpc-common libseccomp2 libblkid1 libuuid1 e2fsprogs openssh-server

{ fetchurl }:

[

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/gcc-16/gcc-16-base_16-20260322-1ubuntu1_amd64.deb";
      sha256 = "281b3188840a7abdca85a02eb2609b0efad852e8994b3804a0e4227ec4ec3f90";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/gcc-16/libgcc-s1_16-20260322-1ubuntu1_amd64.deb";
      sha256 = "2fb4d81c14fdf34251639ae82f5181f9f98480ea16125d535571ac1be9db3065";
    })

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/glibc/libc-gconv-modules-extra_2.43-2ubuntu2_amd64.deb";
      sha256 = "eb5ba6fd4ec1a68801e757f4492c6c6b30119ff277ac9d99629a011559c963f0";
    })

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/glibc/libc6_2.43-2ubuntu2_amd64.deb";
      sha256 = "c13775dc0c984403f3fcad229d14507a9f387763bd07ace1e5f93897ee6b8434";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-3_amd64.deb";
      sha256 = "34365d611ccf1f717f90a92fbe52ed96ae1829ab9be363c68a83563322797f8f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1ubuntu3_amd64.deb";
      sha256 = "c45bbbf9c87457d90b8ba38720c5f01b9388c380d40f303c26f5c4953932da26";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/o/openssl/openssl-provider-legacy_3.5.5-1ubuntu3.2_amd64.deb";
      sha256 = "21261e30caeaaa93f9fbc176cfb022bc4dca1c44988cc23f7a3d1c6138259ff5";
    })

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/o/openssl/libssl3t64_3.5.5-1ubuntu3.2_amd64.deb";
      sha256 = "0bc54d31f00aa7c5a14196ba7dba9352002797da7b67f969b6fd891af9a7f0e6";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/o/openssl/openssl_3.5.5-1ubuntu3.2_amd64.deb";
      sha256 = "9ee8d21c6f19f2a6848e2a26c2966d9813d3dbec1f9823b6d5376317c6ca0d5c";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/d/debconf/debconf_1.5.92_all.deb";
      sha256 = "025984be5dc70b32e02c8a668fdcceba674173bbda4a3e7ff93fac800dcdd122";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/c/ca-certificates/ca-certificates_20260601~26.04.1_all.deb";
      sha256 = "6077d27c6b6f8b23590cb01ff877ed8c804a67a5442cc32b5a33da10d2bd0e90";
      name = "ca-certificates_2026060126.04.1_all.deb";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/elfutils/libelf1t64_0.194-4_amd64.deb";
      sha256 = "c2feae172b14d2a8317348023c5e0b6572314c097a9f7b8225c62b0988cc8d92";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libb/libbpf/libbpf1_1.6.3-1ubuntu1_amd64.deb";
      sha256 = "ec7e4acb71b824e218da4d78496b44827d2a33100e7230732002d3459872e993";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libc/libcap2/libcap2_2.75-10ubuntu2_amd64.deb";
      sha256 = "150603a0792b1d22aa0bde0a26c27b413018c799284003e4b43cba587a5b3a18";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/d/db5.3/libdb5.3t64_5.3.28+dfsg2-10ubuntu1_amd64.deb";
      sha256 = "823df284bbc343ae6e22d69dc14a39c31b6c81fc2bccdd9ed720b88af92fcfa4";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libm/libmnl/libmnl0_1.0.5-3build1_amd64.deb";
      sha256 = "ab5e2781b0e2a2155cf154c658a2e6cf419d95a28c3121aefb159df6453102e5";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/pcre2/libpcre2-8-0_10.46-1build1_amd64.deb";
      sha256 = "3e116766f1a7b149994d4745556023d993d26401223d1595520a991d4ba737fb";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libs/libselinux/libselinux1_3.9-4build1_amd64.deb";
      sha256 = "3ce3aea44b2ec00780c48b1b8e1f7e672166ec3ccac14b0eae8890e55983061e";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/k/krb5/libkrb5support0_1.22.1-2ubuntu4_amd64.deb";
      sha256 = "f9cfb4ba27d0745cbfc7c064cc68f15ea3d6b144a4fd1da9c5f83fe30008aef7";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/libcom-err2_1.47.2-3ubuntu4_amd64.deb";
      sha256 = "180b6ea0b9c07d4fd2ede79e29ee8eca830cd9384f856507e28dc24d1d3ae514";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/k/krb5/libk5crypto3_1.22.1-2ubuntu4_amd64.deb";
      sha256 = "f8a985e1bc63f943db0ca9ada3309edfda4042a3023e36d80c6cf3e9591c557b";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/k/keyutils/libkeyutils1_1.6.3-6ubuntu3_amd64.deb";
      sha256 = "ea7d3cc642ffe2459c35a85c894f80e92499b9eba13bdcb225e0aa751c0970be";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/k/krb5/libkrb5-3_1.22.1-2ubuntu4_amd64.deb";
      sha256 = "bcba1775a914698ba5270f0febb1c47a3fceede86b17c574550d84e0b581dc0f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/k/krb5/libgssapi-krb5-2_1.22.1-2ubuntu4_amd64.deb";
      sha256 = "e9329ba8c8c92b6cb10e3adf8bb75ed6289ada8e4f395550b3f1dc84f251f7ac";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libt/libtirpc/libtirpc-common_1.3.7-0.1_all.deb";
      sha256 = "debc1757cd9b13ec7837e6e76bd9aaf8ae0f622de0e45043e4f5c6e255375814";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libt/libtirpc/libtirpc3t64_1.3.7-0.1_amd64.deb";
      sha256 = "a6c68bbbcbaf2941aee004e581289958c690d17b867be510940a82df2a5572c1";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/i/iptables/libxtables12_1.8.11-2ubuntu3_amd64.deb";
      sha256 = "e21126e0544e3b795633fb5b06bb7f2b9a493ebc5ab07b007db0f7f68c0a0aed";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libc/libcap2/libcap2-bin_2.75-10ubuntu2_amd64.deb";
      sha256 = "d92a8f9affbd2277d191e65978ba2a194d00d00a04f52ee9d1bca2a2ba26697d";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/i/iproute2/iproute2_6.19.0-1ubuntu1_amd64.deb";
      sha256 = "b123740a96966f63cb5ade86ccf0855cbaa89ae87ff7879d1114d3377bc687b8";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-5ubuntu2_amd64.deb";
      sha256 = "a9bbe9d4a4bcd5875bbd0f53e67c379bc881d1c1a80522d51dfb4b107cc31819";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/j/jansson/libjansson4_2.14-2build4_amd64.deb";
      sha256 = "1dc986ac3cf112384919d1a339a952e8a86bede9890a4489c016fdc266a036ca";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libn/libnftnl/libnftnl11_1.3.1-1_amd64.deb";
      sha256 = "a2f4d4a4ce3fac7e473c8de60a3d8948a58e9850cd8e2ced17263aa73dda7199";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/n/nftables/libnftables1_1.1.6-1_amd64.deb";
      sha256 = "0e5abb5719052d9f12aadf91a3f3d5192a2e85d035ee81d07c3055a0f79d8b8f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libm/libmd/libmd0_1.1.0-2build4_amd64.deb";
      sha256 = "da684bb562e167721ae38366586aaee0b4cc580b9ee6d0220128b15ef9c5be75";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libb/libbsd/libbsd0_0.12.2-2build2_amd64.deb";
      sha256 = "62019928a6baeaba8d12d2d4cb7c1e4c9a9550a1eb4541b8de0cacfeae1d09e3";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/n/ncurses/libtinfo6_6.6+20251231-1_amd64.deb";
      sha256 = "42705a701a98d84c203c6f96f08c6fd6a29a1ef978683e1ffbf0e27535b20ddb";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libe/libedit/libedit2_3.1-20251016-1_amd64.deb";
      sha256 = "22338fcbcaae99f67ca7b2e20d1730bc29d3c02bcd2414e457f99be96442ee29";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/n/nftables/nftables_1.1.6-1_amd64.deb";
      sha256 = "fcdeae9ed9761550619d062f8ae87a2399c84ab87f4535bcb9ab0d3649aba59a";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/glibc/libc-bin_2.43-2ubuntu2_amd64.deb";
      sha256 = "c34230e6892fa95e498e51640f7131946120b83eb672f586e341fa53bf504359";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libx/libxml2/libxml2-16_2.15.2+dfsg-0.1ubuntu0.1_amd64.deb";
      sha256 = "14211c45bb75f9543e6053207533370047873ade7e4c70f7285400f1df6c898f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/g/gcc-16/libstdc++6_16-20260322-1ubuntu1_amd64.deb";
      sha256 = "a32b9ad585e39bdc7bd15d1eae6293461e6d466859a1dd2f7862d1e40f89b9d8";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libs/libseccomp/libseccomp2_2.6.0-2ubuntu5_amd64.deb";
      sha256 = "c5e4b198f251da0ede226fd179830bd8767482821a1773f835358f726795cb16";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/u/util-linux/libblkid1_2.41.3-3ubuntu2_amd64.deb";
      sha256 = "f2caf1f807c0b203e5f4545c3010ac34b2dd5f546704e5b1b9c62a41d483771e";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/u/util-linux/libuuid1_2.41.3-3ubuntu2_amd64.deb";
      sha256 = "ea9d94da2fb6564391145f3a9630c140c8dd771a38ae753983e8dc55cc22e102";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/logsave_1.47.2-3ubuntu4_amd64.deb";
      sha256 = "465cb25b468c5f6e883f3ae46c044506e14cdd1aed539a9cc19ce1be8a31d517";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/libext2fs2t64_1.47.2-3ubuntu4_amd64.deb";
      sha256 = "0c58fa90fcb38c1bcc0dbce47b105c60c990128e0220b087f4513d82499d404e";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/libss2_1.47.2-3ubuntu4_amd64.deb";
      sha256 = "08d28bd0e1402f45c1e7c9b28cc65ec55442876217c9f553e8836c0622a71509";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/e/e2fsprogs/e2fsprogs_1.47.2-3ubuntu4_amd64.deb";
      sha256 = "a4343a8c026e1ca8e2e76a5d01abb8c2d6381961a1766b2d2363e3e23cc362ca";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/a/audit/libaudit-common_4.1.2-1build1_all.deb";
      sha256 = "763a89b5c40942860f4d000499579763a2123c1226b3d2a66677846aa304a85d";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libc/libcap-ng/libcap-ng0_0.8.5-4build5_amd64.deb";
      sha256 = "ef20434fbf03076d238155e937870cf389884ae81bd8c3569ff6043aef6da398";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/a/audit/libaudit1_4.1.2-1build1_amd64.deb";
      sha256 = "d3b8aa4efc9851ad9641ef2b1cc13d125c7c45d167e53527c694255d0c47b68f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libx/libxcrypt/libcrypt1_4.5.1-1_amd64.deb";
      sha256 = "57ab343c3dd28ce7101dc4e23de4e9d5bd3e58c6cb0ecd5ba0c42a877fc8868a";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/pam/libpam0g_1.7.0-5ubuntu3_amd64.deb";
      sha256 = "acf0babd7e2da02a1f03981398624f7ad4660eb1ff188b4c9e93a350f98d02cd";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/systemd/libsystemd0_259.5-0ubuntu3_amd64.deb";
      sha256 = "a93b416fd58067a14061763bfc9a23d18b0d4e0914b9a678ff7795e02f71d532";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/pam/libpam-modules-bin_1.7.0-5ubuntu3_amd64.deb";
      sha256 = "18cfdce1831fb38878a9987cacd02b1a69ea7bda545f6e8eb737742defcd24b5";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/pam/libpam-modules_1.7.0-5ubuntu3_amd64.deb";
      sha256 = "13bb794692dbf0f7f5cdaf5df65ef822d22c8499bf1d031dd7eb9c6b0746378e";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/pam/libpam-runtime_1.7.0-5ubuntu3_all.deb";
      sha256 = "9f921930903e1dfa626593a411dba2146c91cdacce724f541a079b181452ef41";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/sysvinit/sysvinit-utils_3.15-5ubuntu1_amd64.deb";
      sha256 = "2439c70d04fa6148b1bf3ae2b77d999d8c0906fbd540c60a2bc0463a43b7a9b3";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/l/lsb/lsb-base_11.6build1_all.deb";
      sha256 = "8599bfa5c1d08bbd2f07639025dbf9442f14a7b978438b186d68079accd5d6d5";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/c/cdebconf/libdebconfclient0_0.280ubuntu1_amd64.deb";
      sha256 = "21f699abaaa7624b0206573f69bf4f7a902d92863f2c9dfba497662c5713456b";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/b/base-passwd/base-passwd_3.6.8_amd64.deb";
      sha256 = "226c75127e46de2bbd8a329ac7e55781ede395ab8a9be0f269250b24c81b9c36";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/shadow/login.defs_4.17.4-2ubuntu3_all.deb";
      sha256 = "3331efa0bfbf0caeed828beddb179e32719f744891359bd28beb489f8f7a9fbd";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/a/acl/libacl1_2.3.2-2_amd64.deb";
      sha256 = "77f8d49c031182bbd6c4fe4ec9ad49edb5d4607f2dac795fc6932dce0e8f541e";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libs/libsemanage/libsemanage-common_3.9-1build1_all.deb";
      sha256 = "09668f05e1a860672d94f31a5ae025d2b41269ff6cc5479554825758ee9dcf3a";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/b/bzip2/libbz2-1.0_1.0.8-6build2_amd64.deb";
      sha256 = "387910c6d79c39c47d83ca729b84c0d30c674a340e3b290ec7b6df3288c19f9a";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libs/libsepol/libsepol2_3.9-2_amd64.deb";
      sha256 = "fbad1d0e81e2b18602bce921697fa14c6dc54c09e790f917e1d512f1fb4c320d";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libs/libsemanage/libsemanage2_3.9-1build1_amd64.deb";
      sha256 = "accd0695703203d9b50cc6325e7f7e849875789cc1f55ba975651e83e3045a76";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/shadow/passwd_4.17.4-2ubuntu3_amd64.deb";
      sha256 = "229301edd46bf07c142eaa87aae3a9d69e6e1f4b57f1d78a7cdbd267fa032182";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/a/adduser/adduser_3.153ubuntu1_all.deb";
      sha256 = "78de3c5c3ec5657bcbdc10c2b2bcd9cedd78e6814182566f1522af422b26d3ce";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/i/init-system-helpers/init-system-helpers_1.69_all.deb";
      sha256 = "49c68d09ceaaf5198966cf1e077ae9bf23d345189cb90e564bcd6594fd83a9fd";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libc/libcbor/libcbor0.10_0.10.2-2ubuntu3_amd64.deb";
      sha256 = "97153fe6f78a737d08227e7df8b185ddb064e69febdea8993ebde37a97b2527f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/systemd/libudev1_259.5-0ubuntu3_amd64.deb";
      sha256 = "c8acd1fcb6b4041be7697692f47289d3e147462fcb5c1df722848a3096e1cbd3";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libf/libfido2/libfido2-1_1.16.0-2build1_amd64.deb";
      sha256 = "e74f757c08a3c9827453de9986101b43ca1069de6be9b8a7eeb438943f73f11f";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/o/openssh/openssh-client_10.2p1-2ubuntu3.5_amd64.deb";
      sha256 = "07496c06fcf80a13eabb1603640cff5bbee3c38468a5f9465eb16981f00e3506";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/o/openssh/openssh-sftp-server_10.2p1-2ubuntu3.5_amd64.deb";
      sha256 = "3732dcfb5da9f375ecd42eece93aeceb0e95d3c8d8df4d94b906dcf863403ef3";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/n/ncurses/libncursesw6_6.6+20251231-1_amd64.deb";
      sha256 = "f41108de5823fee85bd355a06b2939b2c8fe2f6df267c4fa45435544990ec6ff";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/procps/libproc2-0_4.0.4-9ubuntu1_amd64.deb";
      sha256 = "47d00e206617cc92aa319b6b0430f77460826bd7f15c1b3d5171e1646545f9f2";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/procps/procps_4.0.4-9ubuntu1_amd64.deb";
      sha256 = "471b02803d2ff240a28d03059ac9bd676b1f9e25bfd84b8feef95171bbf1da90";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/p/perl/perl-base_5.40.1-7ubuntu0.1_amd64.deb";
      sha256 = "f19be711fcce9708c7d870b87bab8814c2712bee777b08b696c13de88d4edf73";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libt/libtext-charwidth-perl/libtext-charwidth-perl_0.04-11build4_amd64.deb";
      sha256 = "55089bcbe8f6213d500900769f5161e35fb9e4147cf472b469a37e1d1e96a022";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/libt/libtext-wrapi18n-perl/libtext-wrapi18n-perl_0.06-10_all.deb";
      sha256 = "936619071dd5d81ff672b685af9ad20e1f524be2241cbd80556aedc376844a36";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/sensible-utils/sensible-utils_0.0.26build1_all.deb";
      sha256 = "ee67d2df8ac299b20668d93c4817e9db88626b0636cc4cda76b1948e140e364b";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/u/ucf/ucf_3.0052ubuntu1_all.deb";
      sha256 = "42354d322fda598511b62288123e8b4b6daf6b7bbb268d68e8e7f88efa498305";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/u/util-linux/libmount1_2.41.3-3ubuntu2_amd64.deb";
      sha256 = "c0bd8dbe186941f2aaf2b1536d1b48084a7ceda68369afb7f66391b9bcacba36";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/u/util-linux/libsmartcols1_2.41.3-3ubuntu2_amd64.deb";
      sha256 = "a30fdde4eff9088eb91050856b58b7a87abc668a1d88895a9ee670c76f091cb0";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/u/util-linux/mount_2.41.3-3ubuntu2_amd64.deb";
      sha256 = "64e76233a9f5f346f6f4ed90adf98937670b107e08a37ef208adcd28d93b5fd9";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/systemd/libsystemd-shared_259.5-0ubuntu3_amd64.deb";
      sha256 = "a97ce6eef1b3335758024c62ab6175ffcc69b5d3c7e2016ade239c39865a5130";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/s/systemd/systemd_259.5-0ubuntu3_amd64.deb";
      sha256 = "433cf4c5e2d51fc02fb3e7b0a606ca6fda0ea699de193963ff36bc1aa6e80f17";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/t/tcp-wrappers/libwrap0_7.6.q-36build2_amd64.deb";
      sha256 = "a3784ca083c626c3ae41cdd32d4c5898554650dc77d2b54dbb1197a38198adf8";
    })

  ]

  [

    (fetchurl {
      url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/o/openssh/openssh-server_10.2p1-2ubuntu3.5_amd64.deb";
      sha256 = "1d09ade727becb474b78b180902760448f2f8dbdb59df0950f19890402bd1508";
    })

  ]

]
