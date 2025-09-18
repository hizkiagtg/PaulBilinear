# Use a Debian-based Python image
FROM python:3.8

# Make Python logs unbuffered (always flush stdout/stderr)
ENV PYTHONUNBUFFERED=1

# 1. INSTALL SYSTEM DEPENDENCIES
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

# Set working directory for building
WORKDIR /usr/src/build

# 2. BUILD AND INSTALL PBC LIBRARY
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure LDFLAGS="-lgmp" && \
    make && \
    make install && \
    ldconfig

# 3. BUILD AND INSTALL CHARM FROM SOURCE
WORKDIR /usr/src/build
RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm && \
    ./configure.sh --python=/usr/local/bin/python3 && \
    make && \
    make install && \
    ldconfig

# 4. Set the final working directory for our application
WORKDIR /usr/src/app

# Copy application code
COPY src ./src

# Ensure Python finds ./src as a package
ENV PYTHONPATH=/usr/src/app

# Run main script
CMD ["python", "-u", "-m", "src.main"]