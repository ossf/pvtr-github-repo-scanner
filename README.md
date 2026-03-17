# Privateer Plugin for GitHub Repositories

This application performs automated assessments against GitHub repositories using controls defined in the [Open Source Project Security Baseline v2025.02.25](https://baseline.openssf.org). The application consumes the OSPS Baseline controls using [Gemara](https://github.com/gemaraproj/go-gemara) layer 2 and produces results of the automated assessments using layer 4.

Many of the assessments depend upon the presence of a [Security Insights](https://github.com/ossf/security-insights) file at the root of the repository, or `./github/security-insights.yml`.

## Work in Progress

Currently 39 control requirements across OSPS Baselines levels 1-3 are covered, with 13 not yet implemented. [Maturity Level 1](https://baseline.openssf.org/versions/2025-02-25.html#level-1) requirements are the most rigorously tested and are recommended for use. The results of these layer 1 assessments are integrated into [LFX Insights](https://insights.linuxfoundation.org/project/k8s/repository/kubernetes-kubernetes/security), powering the [Security & Best Practices results](https://insights.linuxfoundation.org/docs/metrics/security/).

![alt text](kubernetes_insights_baseline.png)

Level 2 and Level 3 requirements are undergoing current development and may be less rigorously tested.

## Local Usage

To run the GitHub scanner locally, you will need the Privateer (`pvtr`) framework and the GitHub repository scanner (`pvtr-github-repo-scanner`) plugin.

1. Install pvtr using one of the methods described [here](https://github.com/privateerproj/privateer/blob/main/README.md#step-2-choose-your-installation-method).
2. Next, download the `pvtr-github-repo-scanner` plugin from the [releases](https://github.com/ossf/pvtr-github-repo-scanner/releases).

The following command is an example where the `pvtr`, the `pvtr-github-repo-scanner`, and the `config.yaml` are in the same directory.
```sh
./pvtr run --binaries-path .
```
If the binaries and the config files are in different directories specify the complete path using `--binaries-path` and `--config` flags.

You may have to adjust the plugin name in the config.yaml file to match them.

## Docker Usage

```sh
# build the image
docker build . -t local
docker run \
  --mount type=bind,source=./config.yml,destination=/.privateer/config.yml \
  --mount type=bind,source=./evaluation_results,destination=/.privateer/bin/evaluation_results \
  local
```

## GitHub Actions Usage

See the [OSPS Security Baseline Scanner](https://github.com/marketplace/actions/open-source-project-security-baseline-scanner)

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](.github/CONTRIBUTING.md) for more information.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
