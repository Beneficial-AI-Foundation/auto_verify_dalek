FROM docker.io/library/rust@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS tool-builder

ADD --checksum=sha256:7e3e6c36decbd8f1eedd14d42db6674be03671c2204864befa2a41756c5c8fc4 \
  https://www.kernel.org/pub/software/scm/git/git-2.50.1.tar.xz \
  /tmp/git.tar.xz
RUN mkdir -p /src \
    && tar -xJf /tmp/git.tar.xz -C /src \
    && mv /src/git-2.50.1 /src/git \
    && rm /tmp/git.tar.xz
WORKDIR /src/git
RUN make -j"$(nproc)" \
      prefix=/opt/git \
      NO_CURL=YesPlease \
      NO_EXPAT=YesPlease \
      NO_GETTEXT=YesPlease \
      NO_PERL=YesPlease \
      NO_PYTHON=YesPlease \
      NO_TCLTK=YesPlease \
      all \
    && make \
      prefix=/opt/git \
      NO_CURL=YesPlease \
      NO_EXPAT=YesPlease \
      NO_GETTEXT=YesPlease \
      NO_PERL=YesPlease \
      NO_PYTHON=YesPlease \
      NO_TCLTK=YesPlease \
      install

ADD --checksum=sha256:aaf1cb59b5996dd51831c9114b6e3a4a176e197851de91194b473117e142b935 \
  https://static.rust-lang.org/dist/2026-06-01/channel-rust-nightly.toml \
  /tmp/channel-rust-nightly.toml
RUN rustup component add rust-analyzer rust-src \
    && rustup toolchain install nightly-2026-06-01 \
      --profile minimal \
      --component llvm-tools-preview \
      --component rust-src \
      --component rustc-dev \
    && ln -s \
      nightly-2026-06-01-aarch64-unknown-linux-gnu \
      /usr/local/rustup/toolchains/nightly-aarch64-unknown-linux-gnu \
    && rustup set auto-install disable \
    && rm /tmp/channel-rust-nightly.toml

ADD --checksum=sha256:80f55cea4022db86641f1ece5098c9df2f13d79624e61a461d5379dc5d4b7511 \
  https://static.crates.io/crates/cargo-public-api/cargo-public-api-0.52.0.crate \
  /tmp/cargo-public-api-0.52.0.crate
RUN tar -xzf /tmp/cargo-public-api-0.52.0.crate -C /src \
    && rm /tmp/cargo-public-api-0.52.0.crate \
    && printf '\n%s\n%s\n%s\n' \
      '[dependencies.curl-sys]' \
      'version = "=0.4.77"' \
      'features = ["static-curl"]' \
      >> /src/cargo-public-api-0.52.0/Cargo.toml \
    && OPENSSL_STATIC=1 cargo install \
      --locked \
      --path /src/cargo-public-api-0.52.0 \
      --root /opt/cargo-public-api \
    && ! ldd /opt/cargo-public-api/bin/cargo-public-api | grep -F libcurl

ADD --checksum=sha256:ace458df964e9a4bb8d0b18f8a0763269f9768ea9f089393cfed9822c819dc5f \
  https://github.com/sourcegraph/scip/releases/download/v0.6.1/scip-linux-arm64.tar.gz \
  /tmp/scip-linux-arm64.tar.gz
RUN mkdir -p /opt/probe-tools \
    && tar -xzf /tmp/scip-linux-arm64.tar.gz -C /tmp scip \
    && install -m 0555 /tmp/scip /opt/probe-tools/scip \
    && rm /tmp/scip /tmp/scip-linux-arm64.tar.gz

ADD --checksum=sha256:234be1fa539de49b5315843c6aa7c42da0934c425455ea9a4130b4f383eca23e \
  https://github.com/leanprover/lean4/releases/download/v4.28.0-rc1/lean-4.28.0-rc1-linux_aarch64.zip \
  /tmp/lean.zip
RUN unzip -q /tmp/lean.zip -d /opt/lean-release \
    && mv /opt/lean-release/* /opt/lean \
    && rm /tmp/lean.zip

COPY inputs/probe-aeneas.tar.gz inputs/probe-rust.tar.gz inputs/charon.tar.gz /tmp/
RUN printf '%s  %s\n' \
      e362133e1468ddfb1e93e1103f2f58921819edd442cc21885b812e8aea11cf21 /tmp/probe-aeneas.tar.gz \
      3ad84de7f0d5e634527076dedf3fc8ff032503d9774f10dd701b369389d5bc2a /tmp/probe-rust.tar.gz \
      109b382be35447ae164e3e94219eb3b6f4551e4ace6750acacac37946528f663 /tmp/charon.tar.gz \
      | sha256sum --check --strict \
    && tar -xzf /tmp/probe-aeneas.tar.gz -C /src \
    && tar -xzf /tmp/probe-rust.tar.gz -C /src \
    && tar -xzf /tmp/charon.tar.gz -C /src \
    && rm /tmp/probe-aeneas.tar.gz /tmp/probe-rust.tar.gz /tmp/charon.tar.gz
RUN cargo build --locked --release --manifest-path /src/probe-aeneas/Cargo.toml \
    && cargo build --locked --release --manifest-path /src/probe-rust/Cargo.toml \
    && RUSTUP_TOOLCHAIN=nightly-2026-06-01 cargo build \
      --locked \
      --release \
      --manifest-path /src/charon/charon/Cargo.toml

COPY inputs/probe-lean.tar.gz /tmp/probe-lean.tar.gz
RUN printf '%s  %s\n' \
      160ad319283fc863e94d6e273fa1e59a60721edd9b211e161063b8d03f7a0d7b /tmp/probe-lean.tar.gz \
      | sha256sum --check --strict \
    && tar -xzf /tmp/probe-lean.tar.gz -C /src \
    && rm /tmp/probe-lean.tar.gz
ENV PATH="/opt/lean/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKDIR /src/probe-lean
RUN lake build probe-lean \
    && mkdir -p /opt/rust-bin \
    && install -m 0555 /usr/local/cargo/bin/rustup /opt/rust-bin/rustup \
    && for proxy in cargo rustc rustdoc rust-analyzer; do \
      ln -s rustup "/opt/rust-bin/${proxy}"; \
    done \
    && install -m 0555 \
      /opt/cargo-public-api/bin/cargo-public-api \
      /opt/rust-bin/cargo-public-api \
    && rm -rf /usr/local/rustup/downloads/* /usr/local/rustup/tmp/*

FROM docker.io/library/python@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS python-deps

ADD --checksum=sha256:685e47f8f88b6845a9fc2ca27c3d246c0f53af8c017daf8e98ac0a97fe20365b \
  https://github.com/astral-sh/uv/releases/download/0.10.2/uv-aarch64-unknown-linux-musl.tar.gz \
  /tmp/uv.tar.gz
RUN mkdir -p /opt/uv-release \
    && tar -xzf /tmp/uv.tar.gz -C /opt/uv-release \
    && install -D -m 0555 /opt/uv-release/uv-aarch64-unknown-linux-musl/uv /usr/local/bin/uv \
    && rm -rf /tmp/uv.tar.gz /opt/uv-release \
    && python -m venv /opt/autofv-venv \
    && uv pip install \
      --python /opt/autofv-venv/bin/python \
      --no-cache \
      'cryptography==50.0.1' \
      'langgraph==1.2.11' \
      'uv-build==0.12.7'

FROM docker.io/library/python@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c

ARG AUTOFV_BUILD_INPUTS_SHA256=95e1833ea5c4bb941afc1cd0bf4a61cb725aa06771b6bf0b37afb2de61da9b5e
ARG AUTOFV_NATIVE_DECIDE_POLICY_SHA256=bae965de1366b29fa30d89057a218d6030065d43bcf14f4f664a2e63bded7ff9

LABEL org.autofv.toolchain-lock-schema="autofv-toolchain-lock/v1" \
      org.autofv.build-inputs-sha256="${AUTOFV_BUILD_INPUTS_SHA256}" \
      org.autofv.native-decide-policy-sha256="${AUTOFV_NATIVE_DECIDE_POLICY_SHA256}"

ENV HOME="/home/autofv" \
    TMPDIR="/tmp" \
    XDG_CACHE_HOME="/home/autofv/.cache" \
    CARGO_HOME="/home/autofv/.cache/cargo" \
    RUSTUP_HOME="/opt/rustup" \
    RUSTUP_AUTO_INSTALL="0" \
    RUSTUP_NO_UPDATE_CHECK="1" \
    PROBE_SCIP_VERSION="v0.6.1" \
    PROBE_SCIP_SHA256="ace458df964e9a4bb8d0b18f8a0763269f9768ea9f089393cfed9822c819dc5f" \
    GIT_EXEC_PATH="/opt/git/libexec/git-core" \
    PATH="/opt/autofv-venv/bin:/opt/git/bin:/opt/lean/bin:/opt/rust-bin:/usr/local/bin:/usr/bin:/bin"

COPY --from=python-deps /opt/autofv-venv /opt/autofv-venv
COPY --from=python-deps /usr/local/bin/uv /usr/local/bin/uv
COPY --from=tool-builder /opt/git /opt/git
COPY --from=tool-builder /opt/lean /opt/lean
COPY --from=tool-builder /usr/local/rustup /opt/rustup
COPY --from=tool-builder /opt/rust-bin /opt/rust-bin
COPY --from=tool-builder --chmod=0555 /opt/probe-tools/scip /usr/local/bin/scip
COPY --from=tool-builder --chmod=0555 /src/charon/charon/target/release/charon /usr/local/bin/charon
COPY --from=tool-builder --chmod=0555 /src/charon/charon/target/release/charon-driver /usr/local/bin/charon-driver
COPY --from=tool-builder --chmod=0555 /src/probe-aeneas/target/release/probe-aeneas /usr/local/bin/probe-aeneas
COPY --from=tool-builder --chmod=0555 /src/probe-rust/target/release/probe-rust /usr/local/bin/probe-rust
COPY --from=tool-builder --chmod=0555 /src/probe-lean/.lake/build/bin/probe-lean /usr/local/bin/probe-lean
COPY --from=tool-builder /src/probe-lean/.lake/build/lib/lean /usr/local/lib/probe-lean-v4.28.0-rc1

RUN printf '%s\n' \
      'autofv:x:65532:65532:AutoFV worker:/home/autofv:/usr/sbin/nologin' \
      >> /etc/passwd \
    && printf '%s\n' 'autofv:x:65532:' >> /etc/group \
    && mkdir -p /home/autofv/.cache /home/autofv/.local/bin /home/autofv/.local/lib /work \
    && ln /usr/local/bin/probe-lean /home/autofv/.local/bin/probe-lean-v4.28.0-rc1 \
    && ln -s \
      /usr/local/lib/probe-lean-v4.28.0-rc1 \
      /home/autofv/.local/lib/probe-lean-v4.28.0-rc1 \
    && chmod 0555 \
      /home/autofv \
      /home/autofv/.cache \
      /home/autofv/.local \
      /home/autofv/.local/bin \
      /home/autofv/.local/lib \
      /work

WORKDIR /work
USER 65532:65532
CMD ["python", "--version"]
