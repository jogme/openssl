FROM martenseemann/quic-network-simulator-endpoint:latest

# Make sure curl picks up the new openssl
ENV PKG_CONFIG_LIBDIR=/usr/lib64/pkgconfig:/usr/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig/:$PKG_CONFIG_LIBDIR
# Set the environment variable LD_LIBRARY_PATH to ensure we get the right libraries
ENV LD_LIBRARY_PATH=/usr/lib64:/usr/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
# The branch of openssl to clone
ARG OPENSSL_URL=https://github.com/openssl/openssl.git
ARG OPENSSL_BRANCH=master

# Install needed tools
RUN apt-get update && apt-get install -y \
    git make gcc perl cmake build-essential \
    autoconf libtool pkg-config libpsl-dev

WORKDIR /

# build nghttp3
RUN git clone --depth 1 https://github.com/ngtcp2/nghttp3.git && \
    cd nghttp3 && \
    git submodule update --init && \
    autoreconf -i && \
    ./configure --prefix=/usr && \
    make -j 4 check && \
    make install && \
    rm -rf /nghttp3

# download and build openssl 
#RUN git clone --depth 1 -b $OPENSSL_BRANCH $OPENSSL_URL && \
RUN git clone --depth 1 -b "quic_initial_secret_recalculation" "https://github.com/jogme/openssl.git" && \
    cd openssl && \
    ./Configure enable-trace enable-sslkeylog enable-fips enable-demos enable-h3demo enable-hqinterop disable-docs --prefix=/usr --openssldir=/etc/pki/tls && \
    make -j 4 && make install && cp test/quic-openssl-docker/hq-interop/quic-hq-interop /usr/local/bin && \
    cp test/quic-openssl-docker/hq-interop/quic-hq-interop-server /usr/local/bin && \
    cp demos/http3/ossl-nghttp3-demo-server /usr/local/bin && \
    rm -rf /openssl

# Build curl
RUN git clone --depth 1 https://github.com/curl/curl.git && \
    cd curl && \
    autoreconf -fi && ./configure --with-openssl-quic --with-openssl --with-nghttp3 --prefix=/usr && \
    make -j 4 && \
    make install && \
    rm -rf /curl

# jogme
# add only groups of x25519ML-KEM in the config
RUN sed -i 's/\[openssl_init\]/\[openssl_init\]\nssl_conf = ssl_sect/' /etc/pki/tls/openssl.cnf && \
    cp /etc/pki/tls/openssl.cnf /etc/pki/tls/client_config && \
    printf "\n\n[ssl_sect]\nsystem_default = server_section\n\n[server_section]\nGroups = X25519MLKEM768\n" >> /etc/pki/tls/openssl.cnf && \
    printf "\n\n[ssl_sect]\nsystem_default = client_section\n\n[client_section]\nGroups = x25519:secp256r1:secp384r1:secp521r1:X25519MLKEM768\n" >> /etc/pki/tls/client_config

# copy run script and run it
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
RUN apt-get clean
ENTRYPOINT [ "./run_endpoint.sh" ]

