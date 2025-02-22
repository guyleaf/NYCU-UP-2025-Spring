FROM mcr.microsoft.com/devcontainers/cpp:1-debian-12
HEALTHCHECK NONE

ARG DEBIAN_FRONTEND=noninteractive
ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="none"
ARG PERSISTENCE_DIR="/persistence"
ARG BASH_HISTORY="${PERSISTENCE_DIR}/.bash_history"
ARG XDG_CACHE_HOME="${PERSISTENCE_DIR}/.cache"
ENV TZ="Asia/Taipei"

# Adjust the permission of the persistence folder
RUN mkdir "${PERSISTENCE_DIR}" && chown -R vscode:vscode "${PERSISTENCE_DIR}"

# Locale settings
# Referenced from https://github.com/chunying/up-runtime/blob/main/debian/Dockerfile.
RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && /usr/sbin/locale-gen
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Replace apt mirror site
RUN sed -i -e "s/http:\/\/deb\.debian\.org\/debian/http:\/\/debian\.csie\.ntu\.edu\.tw\/debian/" /etc/apt/sources.list.d/debian.sources

RUN dpkg --add-architecture i386 && dpkg --add-architecture amd64 && dpkg --add-architecture arm64
RUN apt-get update && apt-get -y upgrade \
    && apt-get -y install --no-install-recommends man manpages manpages-dev \
    && apt-get -y install --no-install-recommends --reinstall bash-completion \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Modified from https://github.com/chunying/up-runtime/blob/main/debian/Dockerfile.
RUN apt-get update && apt-get install -y --no-install-recommends locales \
	procps iproute2 iputils-ping net-tools netcat-openbsd \
	sudo htop vim gawk rsync tmux diffutils file less tcpdump \
	wget curl git zsh bison flex pkg-config gdb \
	autoconf automake build-essential yasm nasm libcapstone-dev libc6-dbg dpkg-dev \
	python3 python3-pip python3-virtualenv python3-pwntools python3-dev \
	crossbuild-essential-i386 crossbuild-essential-amd64 crossbuild-essential-arm64 \
	libssl-dev:amd64 libpcre2-dev:amd64 zlib1g-dev:amd64 \
	libssl-dev:arm64 libpcre2-dev:arm64 zlib1g-dev:arm64 \
	libssl-dev:i386 libpcre2-dev:i386 zlib1g-dev:i386 \
	qemu-user-static ninja-build \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Optionally install the cmake for vcpkg
COPY ./reinstall-cmake.sh /tmp/

RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
    fi \
    && rm -f /tmp/reinstall-cmake.sh

# Switch to vscode user
USER vscode

# Persist bash history
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=${BASH_HISTORY}" \
    && echo "$SNIPPET" >> "$HOME/.bashrc" \
    && echo "export XDG_CACHE_HOME=${XDG_CACHE_HOME}" >> "$HOME/.bashrc"

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN vcpkg install <your-port-name-here>
