# Lightweight repro image: vanilla Ruby + vulnerable org-ruby 0.9.12.
# Build & run (host needs docker; traffic stays on loopback):
#   docker build -f lab/Dockerfile.ruby -t cve-2026-110264-repro lab
#   docker run --rm -v "$PWD:/work" -w /work cve-2026-110264-repro \
#     ruby lab/repro.rb --generate 35000 /tmp/p0.org
#   docker run --rm -v "$PWD:/work" -w /work cve-2026-110264-repro \
#     ruby lab/repro.rb /tmp/p0.org --budget 8
FROM ruby:3.4-slim
RUN gem install org-ruby -v 0.9.12 --no-document
WORKDIR /work
ENTRYPOINT ["ruby"]
