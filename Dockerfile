# Use a Debian-based Python image
FROM python:3.8

ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    git \
    m4 \
    flex \
    bison \
    libgmp-dev \
    libssl-dev \
    python3-dev \
    python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/build

# Build and install PBC
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure LDFLAGS="-lgmp" && \
    make && \
    make install && \
    ldconfig

# Build and install Charm Crypto
WORKDIR /usr/src/build
RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm && \
    ./configure.sh --python=/usr/local/bin/python3 && \
    make && \
    make install && \
    ldconfig

# Final application stage
WORKDIR /usr/src/app
COPY src ./src
COPY tests ./tests

ENV PYTHONPATH=/usr/src/app \
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

RUN pip install --no-cache-dir 'typing-extensions<4.5' 'pytest<8'

CMD ["python", "-u", "-m", "src.main"]
