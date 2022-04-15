![GitHub release (latest by date)](https://img.shields.io/github/v/release/topicuskeyhub/keyhub-vault-operator)
![Go](https://img.shields.io/github/go-mod/go-version/topicuskeyhub/keyhub-vault-operator)
![GitHub](https://img.shields.io/github/license/topicuskeyhub/keyhub-vault-operator)

![Topicus KeyHub](assets/keyhub.png)

# Topicus KeyHub Vault Operator
Manage Kubernetes Secrets with Topicus KeyHub and the `KeyHubSecret` resource.

## Documentation
The documentation can be found [here](https://topicuskeyhub.github.io/keyhub-vault-operator/).

## Getting started
Run the operator locally. Make sure you are connecting to your local minikube cluster!
```
make run
```

Run the tests
```
make test
```

## Development
- Install [minikube](https://minikube.sigs.k8s.io/docs/) or something similar
- Install [Operator SDK](https://sdk.operatorframework.io/)

### Git pre-commit hook to check Conventional Commits
- Install [`pre-commit`](https://pre-commit.com/#install)
- Install `pre-commit` script ([more info](https://github.com/compilerla/conventional-pre-commit)):
  ```console
  pre-commit install --hook-type commit-msg
  ```

## Install
```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: keyhub-vault-operator

resources:
- ssh://github.com/topicusonderwijs/keyhub-vault-operator//config/default?ref=main
```

## Release
- Manually run the `Release` workflow (branch `main`) from Github Actions.

The `Release` workflow will do the following:
- Update `images['controller'].newTag` in `config/manager/kustomization.yaml` with the full semver (prefixed with a 'v'), e.g. `v0.1.0`. The semver is based on conventional commits and the latest git tag.
- Create and push the release tag, e.g. `v0.1.0`.
- Create a GitHub release with a changelog based on the (conventional) commits since the last release.
- Jenkins will build and publish the image from the release tag.
