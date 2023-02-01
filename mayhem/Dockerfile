# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang libvips-dev
ADD . /src
RUN rm /usr/bin/x86_64-linux-gnu-gcc && ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc
WORKDIR /src
ENV CC=clang
ENV CXX=clang++
ENV CFLAGS="-fsanitize=undefined,fuzzer-no-link"
ENV CXXFLAGS="-fsanitize=undefined,fuzzer-no-link"
RUN python3 -m pip install .

ENV LD_PRELOAD="${LD_PRELOAD}"
CMD ["/src/mayhem/fuzz_parse.py"]