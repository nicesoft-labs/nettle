# Build Instructions for nettle

To compile nettle from a git checkout on Ubuntu/Debian systems you need the following packages:

```sh
sudo apt-get update
sudo apt-get install -y autoconf automake libtool build-essential m4 libgmp-dev pkg-config
```

Then run the bootstrap script to generate `configure`, configure, build and run the tests:

```sh
./.bootstrap
./configure --disable-documentation
make -j$(nproc)
make check -j$(nproc)
```

All tests should pass, including `kuznyechik` to verify the Grasshopper cipher implementation.
