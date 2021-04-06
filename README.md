![Topicus KeyHub](assets/keyhub.png)

# Topicus KeyHub Vault Operator
Manage Kubernetes Secrets with Topicus KeyHub and the `KeyHubSecret` resource.

## Documentation
To learn more about using KeyHub as a Kubernetes secret store go to [this article](https://kb.topicus.education/docs/devops/kubernetes/keyhub/) in our Knowledge Base.

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

## Release
- Use a release branch `release-x.y`, e.g. `release-0.1`
- Update `images['controller'].newTag` in `config/manager/kustomization.yaml` with the full semver (prefixed with a 'v'), e.g. `v0.1.0`
- Create and push the tag `v0.1.0`
- Jenkins will build and publish the image
