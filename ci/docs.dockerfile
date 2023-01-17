FROM rust AS build

RUN apt update -y -qq && \
    apt install -y -qq --no-install-recommends ca-certificates pandoc && \
    apt clean

COPY doc /public
COPY README.md /public
WORKDIR /public
RUN pandoc --css=tufte.min.css -s -f markdown+smart --metadata pagetitle="PySequoia" --toc --to=html5 README.md -o index.html

FROM scratch
COPY --from=build /public /
