
caliper bind --caliper-bind-sut sawtooth:1.0.0

caliper benchmark run --caliper-workspace . --caliper-networkconfig network-config.yaml --caliper-benchconfig benchmark-config.yaml


