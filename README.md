![Topicus KeyHub](assets/keyhub.png)

# Topicus KeyHub Vault Operator
Manage Kubernetes Secrets with Topicus KeyHub with a `KeyHubSecret` resource.

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
